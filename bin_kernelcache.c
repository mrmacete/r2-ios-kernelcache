/* radare2 - LGPL - Copyright 2018 - mrmacete */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_syscall.h>

// #include "../format/mach0/mach0_defines.h"
#define R_BIN_MACH064 1
#include "format/mach0/mach0.h"

#include "r_cf_dict.h"

typedef struct _RKernelCacheObj {
	RBuffer * cache_buf;
	RCFValueDict * prelink_info;
	ut64 pa2va_exec;
	ut64 pa2va_data;
	struct _RKextIndex * kexts;
	struct MACH0_(obj_t) * mach0;
} RKernelCacheObj;

typedef struct _RFileRange {
	ut64 offset;
	ut64 size;
} RFileRange;

typedef struct _RPrelinkRange {
	RFileRange range;
	ut64 pa2va_exec;
	ut64 pa2va_data;
} RPrelinkRange;

typedef struct _RStubsInfo {
	RFileRange got;
	RFileRange stubs;
	ut64 got_addr;
} RStubsInfo;

typedef struct _RKext {
	RFileRange range;
	RFileRange text_range;
	char * name;
	ut64 mod_info;
	ut64 vaddr;
	struct MACH0_(obj_t) * mach0;
} RKext;

typedef struct _RKextIndex {
	ut64 length;
	RKext **entries;
} RKextIndex;

#define KEXT_SHORT_NAME(kext) ({\
	const char * sn = strrchr (kext->name, '.');\
	sn ? sn + 1 : kext->name;\
})

/*
 * com.apple.driver.AppleMesaSEPDriver.3.__TEXT_EXEC.__text
 *                       |
 *                       |
 * AppleMesaSEPDriver <--+
 */
#define KEXT_SHORT_NAME_FROM_SECTION(io_section) ({\
	char * result = NULL;\
	char * clone = strdup (io_section->name);\
	char * cursor = strstr (clone, "__");\
	if (cursor) {\
		cursor--;\
		*cursor = 0;\
		cursor--;\
		cursor = strrchr (cursor, '.');\
		if (cursor) {\
			*cursor = 0;\
			cursor = strrchr (cursor, '.');\
			if (cursor) {\
				result = strdup (cursor + 1);\
				R_FREE (clone);\
			}\
		}\
	}\
	result ? result : clone;\
})

#define KEXT_INFER_VSIZE(index, i)\
	((i+1 < index->length) ? index->entries[i+1]->vaddr - index->entries[i]->vaddr : UT64_MAX)

#define KEXT_INFER_PSIZE(index, i)\
	((i+1 < index->length) ? index->entries[i+1]->range.offset - index->entries[i]->range.offset : UT64_MAX)

#define R_K_CONSTRUCTOR_TO_ENTRY 0
#define R_K_CONSTRUCTOR_TO_SYMBOL 1

static RPrelinkRange *get_prelink_info_range(const ut8 *header_bytes, ut64 length);
static RPrelinkRange *get_prelink_info_range_from_mach0(struct MACH0_(obj_t) * mach0);
static RList * filter_kexts(RKernelCacheObj * obj);

static void sections_from_mach0(RList * ret, struct MACH0_(obj_t) * mach0, RBinFile *bf, ut64 paddr, char * prefix);
static void handle_data_sections(RBinSection *sect);
static void symbols_from_mach0(RList *ret, struct MACH0_(obj_t) * mach0, RBinFile *bf, ut64 paddr, int ordinal);
static RList *resolve_syscalls(RKernelCacheObj * obj, ut64 enosys_addr);
static void symbols_from_stubs(RList *ret, SdbHash *kernel_syms_by_addr, RKernelCacheObj * obj, RBinFile *bf, RKext * kext, int ordinal);
static RStubsInfo *get_stubs_info(struct MACH0_(obj_t) * mach0, ut64 paddr);
static int prot2perm (int x);

static void r_kext_free(RKext * kext);
static void r_kext_fill_text_range(RKext * kext);
static int kexts_sort_vaddr_func(const void *a, const void *b);
static int kexts_sort_paddr_func(const void *a, const void *b);
static struct MACH0_(obj_t) * create_kext_mach0(RKernelCacheObj * obj, RKext * kext);

#define r_kext_index_foreach(index, i, item)\
	if (index)\
		for (i = 0; i < index->length && (item = index->entries[i], 1); i++)

static RKextIndex * r_kext_index_new(RList * kexts);
static void r_kext_index_free(RKextIndex * index);
static RKext *r_kext_index_vget(RKextIndex *index, ut64 vaddr);
static RKext *r_kext_index_pget(RKextIndex *index, ut64 offset);

static void process_constructors(RKernelCacheObj *obj, struct MACH0_(obj_t) *mach0, RList *ret, ut64 paddr, bool is_first, int mode, const char *prefix);
static RBinAddr* newEntry(ut64 haddr, ut64 vaddr, int type);

static void r_kernel_cache_free(RKernelCacheObj * obj);

static void *load_buffer(RBinFile *bf, RBuffer *buf, ut64 loadaddr, Sdb * sdb) {
	RBuffer *fbuf = r_buf_ref (buf);
	//RBuffer *fbuf = r_buf_new_with_io (&bf->rbin->iob, bf->fd);
	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default) (&opts, bf);
	struct MACH0_(obj_t) *main_mach0 = MACH0_(new_buf) (fbuf, &opts);
	if (!main_mach0) {
		return NULL;
	}

	RPrelinkRange * prelink_range = get_prelink_info_range_from_mach0 (main_mach0);
	if (!prelink_range) {
		goto beach;
	}

	RKernelCacheObj * obj = R_NEW0 (RKernelCacheObj);
	if (!obj) {
		goto beach;
	}

	RCFValueDict * prelink_info = r_cf_value_dict_parse (fbuf, prelink_range->range.offset,
		prelink_range->range.size, R_CF_OPTION_SKIP_NSDATA);
	if (!prelink_info) {
		R_FREE (obj);
		goto beach;
	}

	obj->mach0 = main_mach0;
	obj->prelink_info = prelink_info;
	obj->cache_buf = fbuf;
	obj->pa2va_exec = prelink_range->pa2va_exec;
	obj->pa2va_data = prelink_range->pa2va_data;

	RList * kexts = filter_kexts (obj);
	if (!kexts || !r_list_length (kexts)) {
		r_cf_value_dict_free (prelink_info);
		R_FREE (obj);
		goto beach;
	}

	obj->kexts = r_kext_index_new (kexts);

	return obj;

beach:
	r_buf_free (fbuf);
	MACH0_(mach0_free) (main_mach0);
	return NULL;
}

static RPrelinkRange *get_prelink_info_range_from_mach0(struct MACH0_(obj_t) * mach0) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (mach0))) {
		return NULL;
	}

	RPrelinkRange * prelink_range = R_NEW0 (RPrelinkRange);
	if (!prelink_range) {
		return NULL;
	}

	int incomplete = 3;
	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr (sections[i].name, "__PRELINK_INFO.__info")) {
			prelink_range->range.offset = sections[i].offset;
			prelink_range->range.size = sections[i].size;
			if (!--incomplete) {
				break;
			}
		}

		if (strstr (sections[i].name, "__PRELINK_TEXT.__text")) {
			prelink_range->pa2va_exec = sections[i].addr - sections[i].offset;
			if (!--incomplete) {
				break;
			}
		}

		if (strstr (sections[i].name, "__PRELINK_DATA.__data")) {
			prelink_range->pa2va_data = sections[i].addr - sections[i].offset;
			if (!--incomplete) {
				break;
			}
		}
	}

	R_FREE (sections);

	if (incomplete) {
		R_FREE (prelink_range);
	}

	return prelink_range;
}

static RPrelinkRange *get_prelink_info_range(const ut8 *header_bytes, ut64 length) {
	struct MACH0_(mach_header)  *h64 = (struct MACH0_(mach_header)*) header_bytes;
	struct load_command *cmd = (struct load_command*) (header_bytes + sizeof (struct MACH0_(mach_header)));
	struct load_command *end = (struct load_command*)((const ut8*)cmd + h64->sizeofcmds);
	if ((ut8*) end > (header_bytes + length)) {
		return NULL;
	}

	RPrelinkRange * prelink_range = R_NEW0 (RPrelinkRange);
	if (!prelink_range) {
		return NULL;
	}

	int incomplete = 3;
	for (; cmd < end; cmd = (void *)((const ut8*)cmd + cmd->cmdsize)) {
		if (cmd->cmd != LC_SEGMENT_64) {
			continue;
		}
		struct segment_command_64 * segment = (struct segment_command_64*) cmd;
		if (!strncmp (segment->segname, "__PRELINK_INFO", 16)) {
			prelink_range->range.offset = segment->fileoff;
			prelink_range->range.size = segment->filesize;
			if (!--incomplete) {
				return prelink_range;
			}
		}

		if (!strncmp (segment->segname, "__PRELINK_TEXT", 16)) {
			prelink_range->pa2va_exec = segment->vmaddr - segment->fileoff;
			if (!--incomplete) {
				return prelink_range;
			}
		}

		if (!strncmp (segment->segname, "__PRELINK_DATA", 16)) {
			prelink_range->pa2va_data = segment->vmaddr - segment->fileoff;
			if (!--incomplete) {
				return prelink_range;
			}
		}

		if ((int)cmd->cmdsize < 1) {
			eprintf ("CMD Size FAIL %d\n", cmd->cmdsize);
			break;
		}
	}

	R_FREE (prelink_range);

	return NULL;
}

static RList * filter_kexts(RKernelCacheObj * obj) {
	RCFValueArray * kext_array = NULL;
	RListIter * iter;
	RCFKeyValue * item;
	r_list_foreach (obj->prelink_info->pairs, iter, item) {
		if (!strcmp (item->key, "_PrelinkInfoDictionary")) {
			kext_array = (RCFValueArray*) item->value;
			break;
		}
	}

	if (!kext_array) {
		return NULL;
	}

	RList * kexts = r_list_newf ((RListFree) &r_kext_free);
	if (!kexts) {
		return NULL;
	}

	bool is_sorted = true;
	RKext * prev_kext = NULL;
	RCFValueDict * kext_item;
	r_list_foreach (kext_array->values, iter, kext_item) {
		RKext * kext = R_NEW0 (RKext);
		if (!kext) {
			R_FREE (kexts);
			return NULL;
		}

		int kext_incomplete = 5;
		RListIter * internal_iter;
		r_list_foreach (kext_item->pairs, internal_iter, item) {
			if (!strcmp (item->key, "CFBundlePackageType")) {
				if (item->value->type != R_CF_STRING) {
					break;
				}
				RCFValueString * type = (RCFValueString*) item->value;
				if (strcmp (type->value, "KEXT")) {
					break;
				}
				kext_incomplete--;
			}

			if (!strcmp (item->key, "_PrelinkExecutableLoadAddr")) {
				if (item->value->type == R_CF_INTEGER) {
					kext_incomplete--;
					kext->vaddr = ((RCFValueInteger*) item->value)->value;
					kext->range.offset = kext->vaddr - obj->pa2va_exec;
				}
			}

			if (!strcmp (item->key, "_PrelinkExecutableSize")) {
				kext_incomplete--;
				if (item->value->type == R_CF_INTEGER) {
					kext->range.size = ((RCFValueInteger*) item->value)->value;
				} else {
					kext->range.size = 0;
				}
			}

			if (!strcmp (item->key, "_PrelinkKmodInfo")) {
				if (item->value->type == R_CF_INTEGER) {
					kext_incomplete--;
					kext->mod_info = ((RCFValueInteger*) item->value)->value;
					kext->mod_info -= obj->pa2va_data;
				}
			}

			if (!strcmp (item->key, "CFBundleIdentifier")) {
				if (item->value->type == R_CF_STRING) {
					kext_incomplete--;
					kext->name = ((RCFValueString*) item->value)->value;
				}
			}
		}

		if (kext_incomplete) {
			r_kext_free (kext);
			continue;
		}

		if (prev_kext && kext->vaddr < prev_kext->vaddr) {
			is_sorted = false;
		}
		prev_kext = kext;

		kext->mach0 = create_kext_mach0 (obj, kext);
		if (!kext->mach0) {
			r_kext_free (kext);
			continue;
		}

		r_kext_fill_text_range (kext);

		r_list_push (kexts, kext);
	}

	if (!is_sorted) {
		eprintf ("SORTING KEXTs...\n");
		//r_list_sort (kexts, kexts_sort_vaddr_func);
	} else {
		eprintf ("already sorted!\n");
	}

	return kexts;
}

static void r_kext_free(RKext * kext) {
	if (!kext) {
		return;
	}

	if (kext->mach0) {
		MACH0_(mach0_free) (kext->mach0);
		kext->mach0 = NULL;
	}

	R_FREE (kext);
}

static void r_kext_fill_text_range(RKext * kext) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (kext->mach0))) {
		return;
	}

	RList * syscalls = NULL;
	RSyscall * syscall = NULL;
	ut8 * data_const = NULL;
	ut64 data_const_offset = 0, data_const_size = 0, data_const_vaddr = 0;
	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr (sections[i].name, "__TEXT_EXEC.__text")) {
			kext->text_range.offset = sections[i].offset;
			kext->text_range.size = sections[i].size;
			kext->vaddr = sections[i].addr;
			break;
		}
	}

	R_FREE (sections);
}

static int kexts_sort_vaddr_func(const void *a, const void *b) {
	RKext *A = (RKext *) a;
	RKext *B = (RKext *) b;
	int vaddr_compare = A->vaddr - B->vaddr;
	if (vaddr_compare == 0) {
		return A->text_range.size - B->text_range.size;
	}
	return vaddr_compare;
}

static int kexts_sort_paddr_func(const void *a, const void *b) {
	RKext *A = (RKext *) a;
	RKext *B = (RKext *) b;
	int paddr_compare = A->text_range.offset - B->text_range.offset;
	if (paddr_compare == 0) {
		return A->text_range.size - B->text_range.size;
	}
	return paddr_compare;
}

static RKextIndex * r_kext_index_new(RList * kexts) {
	if (!kexts) {
		return NULL;
	}

	int length = r_list_length (kexts);
	if (!length) {
		return NULL;
	}

	RKextIndex * index = R_NEW0 (RKextIndex);
	if (!index) {
		return NULL;
	}

	index->entries = malloc (length * sizeof(RKext*));
	if (!index->entries) {
		R_FREE (index);
		return NULL;
	}

	RListIter * iter;
	RKext * kext;
	int i = 0;
	r_list_foreach (kexts, iter, kext) {
		index->entries[i++] = kext;
	}
	index->length = i;

	return index;
}

static void r_kext_index_free(RKextIndex * index) {
	if (!index) {
		return;
	}

	int i = 0;
	RKext * kext;
	r_kext_index_foreach (index, i, kext) {
		r_kext_free (kext);
		index->entries[i] = NULL;
	}

	index->length = 0;
	R_FREE (index);
}

static RKext *r_kext_index_vget(RKextIndex *index, ut64 vaddr) {
	int imid;
	int imin = 0;
	int imax = index->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RKext *entry = index->entries[imid];
		if ((entry->vaddr + entry->text_range.size) <= vaddr || (entry->vaddr == vaddr && entry->text_range.size == 0)) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RKext *minEntry = index->entries[imin];
	if ((imax == imin) && (minEntry->vaddr <= vaddr) && ((minEntry->vaddr + minEntry->text_range.size) > vaddr)) {
		return minEntry;
	}
	return NULL;
}

static RKext *r_kext_index_pget(RKextIndex *index, ut64 offset) {
	int imid;
	int imin = 0;
	int imax = index->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RKext *entry = index->entries[imid];
		if ((entry->text_range.offset + entry->text_range.size) <= offset || (entry->range.offset == offset && entry->text_range.size == 0)) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RKext *minEntry = index->entries[imin];
	ut64 minEntry_size = KEXT_INFER_PSIZE (index, imin);
	if ((imax == imin) && (minEntry->text_range.offset <= offset) && ((minEntry->text_range.offset + minEntry->text_range.size) > offset)) {
		return minEntry;
	}
	return NULL;
}

static struct MACH0_(obj_t) * create_kext_mach0(RKernelCacheObj * obj, RKext * kext) {
	/*int sz = 1024 * 1024 * 2;

	ut8 * bytes = malloc (sz);
	if (!bytes) {
		return NULL;
	}

	sz = r_buf_read_at (obj->cache_buf, kext->range.offset, bytes, sz);

	RBuffer *buf = r_buf_new ();
	r_buf_set_bytes_steal (buf, bytes, sz);*/
	RBuffer * buf = r_buf_new_slice (obj->cache_buf, kext->range.offset, UT64_MAX);
	struct MACH0_(opts_t) opts;
	opts.verbose = true;
	opts.header_at = 0;
	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf) (buf, &opts);
	r_buf_free (buf);
	if (!mach0) {
		return NULL;
	}

	return mach0;
}

static RList* entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	RBinObject *obj = bf ? bf->o : NULL;
	struct addr_t *entry = NULL;

	if (!obj || !obj->bin_obj || !(ret = r_list_newf (free))) {
		return NULL;
	}

	RKernelCacheObj *kobj = (RKernelCacheObj*) obj->bin_obj;
	/*if (!(entry = MACH0_(get_entrypoint) (kobj->mach0))) {
		return ret;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = entry->offset + obj->boffset;
		ptr->vaddr = entry->addr;
		ptr->haddr = entry->haddr;
		ptr->bits = 64;
		r_list_append (ret, ptr);
	}
	free (entry);*/

	process_constructors (kobj, kobj->mach0, ret, 0, true, R_K_CONSTRUCTOR_TO_ENTRY, NULL);

	return ret;
}

static void process_constructors(RKernelCacheObj *obj, struct MACH0_(obj_t) *mach0, RList *ret, ut64 paddr, bool is_first, int mode, const char *prefix) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (mach0))) {
		return;
	}
	int i, type;
	for (i = 0; !sections[i].last; i++) {
		if (sections[i].size == 0) {
			continue;
		}

		if (strstr (sections[i].name, "_mod_fini_func") || strstr (sections[i].name, "_mod_term_func")) {
			type  = R_BIN_ENTRY_TYPE_FINI;
		} else if (strstr (sections[i].name, "_mod_init_func")) {
			type  = is_first ? 0 : R_BIN_ENTRY_TYPE_INIT;
			is_first = false;
		} else {
			continue;
		}

		ut8 *buf = calloc (sections[i].size, 1);
		if (!buf) {
			break;
		}
		if (r_buf_read_at (obj->cache_buf, sections[i].offset + paddr, buf, sections[i].size) < sections[i].size) {
			free (buf);
			break;
		}
		int j;
		int count = 0;
		for (j = 0; j < sections[i].size; j += 8) {
			ut64 addr64 = r_read_le64 (buf + j);
			ut64 paddr64 = sections[i].offset + paddr + j;
			if (mode == R_K_CONSTRUCTOR_TO_ENTRY) {
				RBinAddr *ba = newEntry (paddr64, addr64, type);
				r_list_append (ret, ba);
			} else if (mode == R_K_CONSTRUCTOR_TO_SYMBOL) {
				RBinSymbol * sym = R_NEW0 (RBinSymbol);
				if (!sym) {
					break;
				}

				sym->name = r_str_newf ("%s.%s.%d", prefix, (type == R_BIN_ENTRY_TYPE_INIT) ? "init" : "fini", count++);
				sym->vaddr = addr64;
				sym->paddr = paddr64;
				sym->size = 0;
				sym->forwarder = r_str_const ("NONE");
				sym->bind = r_str_const ("GLOBAL");
				sym->type = r_str_const ("FUNC");

				r_list_append (ret, sym);
			}
		}
		free (buf);
	}
	free (sections);
}

static RBinAddr* newEntry(ut64 haddr, ut64 vaddr, int type) {
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (!ptr) {
		return NULL;
	}
	ptr->paddr = haddr;
	ptr->vaddr = vaddr;
	ptr->hpaddr = haddr;
	ptr->bits = 64;
	ptr->type = type;
	return ptr;
}

static bool check_bytes(const ut8 *buf, ut64 length) {
	RPrelinkRange * prelink_range = get_prelink_info_range (buf, length);
	if (!prelink_range) {
		return false;
	}
	return true;
}

static void *load_bytes(RBinFile *bf, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	return (void *) (size_t) check_bytes (buf, sz);
}

static RList* sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	RBinObject *obj = bf ? bf->o : NULL;

	if (!obj || !obj->bin_obj || !(ret = r_list_newf ((RListFree)free))) {
		return NULL;
	}

	RKernelCacheObj * kobj = (RKernelCacheObj*) obj->bin_obj;

	int iter;
	RKext * kext;
	r_kext_index_foreach (kobj->kexts, iter, kext) {
		ut8 magicbytes[4];

		r_buf_read_at (kobj->cache_buf, kext->range.offset, magicbytes, 4);
		int magic = r_read_le32 (magicbytes);
		switch (magic) {
		case MH_MAGIC_64:
			sections_from_mach0 (ret, kext->mach0, bf, kext->range.offset, kext->name);
			break;
		default:
			eprintf ("Unknown sub-bin\n");
			break;
		}
	}

	sections_from_mach0 (ret, kobj->mach0, bf, 0, NULL);

	struct MACH0_(segment_command) *seg;
	int nsegs = R_MIN (kobj->mach0->nsegs, 128);
	int i;
	for (i = 0; i < nsegs; i++) {
		RBinSection * ptr;
		char segname[17];

		if (!(ptr = R_NEW0 (RBinSection))) {
			break;
		}

		seg = &kobj->mach0->segs[i];
		r_str_ncpy (segname, seg->segname, 17);
		r_str_filter (segname, -1);

		r_snprintf (ptr->name, R_BIN_SIZEOF_STRINGS, "%d.%s", i, segname);
		ptr->name[R_BIN_SIZEOF_STRINGS] = 0;
		ptr->size = seg->vmsize;
		ptr->vsize = seg->vmsize;
		ptr->paddr = seg->fileoff + bf->o->boffset;
		ptr->vaddr = seg->vmaddr;
		ptr->add = true;
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->srwx = prot2perm (seg->initprot);
		r_list_append (ret, ptr);
	}

	return ret;
}

static int prot2perm (int x) {
	int r = 0;
	if (x&1) r |= 4;
	if (x&2) r |= 2;
	if (x&4) r |= 1;
	return r;
}

static void sections_from_mach0(RList * ret, struct MACH0_(obj_t) * mach0, RBinFile *bf, ut64 paddr, char * prefix) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (mach0))) {
		return;
	}
	int i;
	for (i = 0; !sections[i].last; i++) {
		/*if (strstr (sections[i].name, "__PLK_TEXT_EXEC.__text")) {
			continue;
		}*/

		RBinSection * ptr;
		if (!(ptr = R_NEW0 (RBinSection))) {
			break;
		}
		if (prefix) {
			r_snprintf (ptr->name, R_BIN_SIZEOF_STRINGS, "%s.%s", prefix, (char*)sections[i].name);
		} else {
			r_snprintf (ptr->name, R_BIN_SIZEOF_STRINGS, "%s", (char*)sections[i].name);
		}
		if (strstr (ptr->name, "la_symbol_ptr")) {
			int len = sections[i].size / 8;
			ptr->format = r_str_newf ("Cd %d[%d]", 8, len);
		}
		ptr->name[R_BIN_SIZEOF_STRINGS] = 0;
		handle_data_sections (ptr);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->paddr = sections[i].offset + bf->o->boffset + paddr;
		ptr->vaddr = sections[i].addr;
		ptr->add = true;
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->srwx = sections[i].srwx;
		r_list_append (ret, ptr);
	}
	free (sections);
}

static void handle_data_sections(RBinSection *sect) {
	if (strstr (sect->name, "_cstring")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_os_log")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_methname")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_classname")) {
		sect->is_data = true;
	} else if (strstr (sect->name, "_objc_methtype")) {
		sect->is_data = true;
	}
}

static RList* symbols(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RKernelCacheObj *obj = (RKernelCacheObj*) bf->o->bin_obj;

	symbols_from_mach0 (ret, obj->mach0, bf, 0, 0);

	SdbHash *kernel_syms_by_addr = sdb_ht_new ();
	if (!kernel_syms_by_addr) {
		r_list_free (ret);
		return NULL;
	}

	RListIter * iter;
	RBinSymbol *sym;
	ut64 enosys_addr = 0;
	r_list_foreach (ret, iter, sym) {
		const char *key = sdb_fmt ("%"PFMT64x, sym->vaddr);
		sdb_ht_insert (kernel_syms_by_addr, key, sym->dname ? sym->dname : sym->name);
		if (!enosys_addr && strstr (sym->name, "enosys")) {
			enosys_addr = sym->vaddr;
		}
	}

	RList * syscalls = resolve_syscalls (obj, enosys_addr);
	if (syscalls) {
		r_list_foreach (syscalls, iter, sym) {
			const char *key = sdb_fmt ("%"PFMT64x, sym->vaddr);
			sdb_ht_insert (kernel_syms_by_addr, key, sym->name);
			r_list_append (ret, sym);
		}
		syscalls->free = NULL;
		r_list_free (syscalls);
	}

	RKext * kext;
	int kiter;
	r_kext_index_foreach (obj->kexts, kiter, kext) {
		ut8 magicbytes[4];
		r_buf_read_at (obj->cache_buf, kext->range.offset, magicbytes, 4);
		int magic = r_read_le32 (magicbytes);
		switch (magic) {
		case MH_MAGIC_64:
			symbols_from_mach0 (ret, kext->mach0, bf, kext->range.offset, r_list_length (ret));
			symbols_from_stubs (ret, kernel_syms_by_addr, obj, bf, kext, r_list_length (ret));
			process_constructors (obj, kext->mach0, ret, kext->range.offset, false, R_K_CONSTRUCTOR_TO_SYMBOL, KEXT_SHORT_NAME (kext));

			break;
		default:
			eprintf ("Unknown sub-bin\n");
			break;
		}
	}

	sdb_ht_free (kernel_syms_by_addr);

	return ret;
}

static void symbols_from_mach0(RList *ret, struct MACH0_(obj_t) * mach0, RBinFile *bf, ut64 paddr, int ordinal) {
	struct symbol_t *symbols = MACH0_(get_symbols) (mach0);
	if (!symbols) {
		return;
	}
	int i;
	for (i = 0; !symbols[i].last; i++) {
		if (!symbols[i].name[0] || symbols[i].addr < 100) {
			continue;
		}
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			break;
		}
		sym->name = strdup (symbols[i].name);
		sym->vaddr = symbols[i].addr;
		if (sym->name[0] == '_') {
			char *dn = r_bin_demangle (bf, sym->name, sym->name, sym->vaddr);
			if (dn) {
				sym->dname = dn;
				char *p = strchr (dn, '.');
				if (p) {
					if (IS_UPPER (sym->name[0])) {
						sym->classname = strdup (sym->name);
						sym->classname[p - sym->name] = 0;
					} else if (IS_UPPER (p[1])) {
						sym->classname = strdup (p + 1);
						p = strchr (sym->classname, '.');
						if (p) {
							*p = 0;
						}
					}
				}
			}
		}
		sym->forwarder = r_str_const ("NONE");
		sym->bind = r_str_const ((symbols[i].type == R_BIN_MACH0_SYMBOL_TYPE_LOCAL)?
			"LOCAL": "GLOBAL");
		sym->type = r_str_const ("FUNC");
		sym->paddr = symbols[i].offset + bf->o->boffset + paddr;
		sym->size = symbols[i].size;
		sym->ordinal = ordinal + i;
		r_list_append (ret, sym);
	}
	free (symbols);
}

#define IS_KERNEL_ADDR(x) ((x & 0xfffffff000000000L) == 0xfffffff000000000L)

typedef struct _r_sysent {
	ut64 sy_call;
	ut64 sy_arg_munge32;
	st32 sy_return_type;
	st16 sy_narg;
	ut16 sy_arg_bytes;
} RSysEnt;

static RList *resolve_syscalls(RKernelCacheObj * obj, ut64 enosys_addr) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (obj->mach0))) {
		return NULL;
	}

	RList * syscalls = NULL;
	RSyscall * syscall = NULL;
	ut8 * data_const = NULL;
	ut64 data_const_offset = 0, data_const_size = 0, data_const_vaddr = 0;
	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr (sections[i].name, "__DATA_CONST.__const")) {
			data_const_offset = sections[i].offset;
			data_const_size = sections[i].size;
			data_const_vaddr = sections[i].addr;
			break;
		}
	}

	if (!data_const_offset || !data_const_size || !data_const_vaddr) {
		goto beach;
	}

	data_const = malloc (data_const_size);
	if (r_buf_read_at (obj->cache_buf, data_const_offset, data_const, data_const_size) < data_const_size) {
		goto beach;
	}

	ut8 *cursor = data_const;
	ut8 *end = data_const + data_const_size;
	while (cursor < end) {
		ut64 test = r_read_le64 (cursor);
		if (test == enosys_addr) {
			break;
		}
		cursor += 8;
	}

	if (cursor >= end) {
		goto beach;
	}

	cursor -= 24;
	while (cursor >= data_const) {
		ut64 addr = r_read_le64 (cursor);
		ut64 x = r_read_le64 (cursor + 8);
		ut64 y = r_read_le64 (cursor + 16);

		if (IS_KERNEL_ADDR (addr) &&
			(x == 0 || IS_KERNEL_ADDR (x)) &&
			(y != 0 && !IS_KERNEL_ADDR (y))) {
			cursor -= 24;
			continue;
		}

		cursor += 24;
		break;
	}

	if (cursor < data_const) {
		goto beach;
	}

	syscalls = r_list_newf (r_bin_symbol_free);
	if (!syscalls) {
		goto beach;
	}

	syscall = r_syscall_new ();
	if (!syscall) {
		goto beach;
	}
	r_syscall_setup (syscall, "arm", 64, NULL, "ios");
	if (!syscall->db) {
		r_syscall_free (syscall);
		goto beach;
	}

	ut64 sysent_vaddr = cursor - data_const + data_const_vaddr;

	RBinSymbol * sym = R_NEW0 (RBinSymbol);
	if (!sym) {
		goto beach;
	}

	sym->name = r_str_newf ("sysent");
	sym->vaddr = sysent_vaddr;
	sym->paddr = cursor - data_const + data_const_offset;
	sym->size = 0;
	sym->forwarder = r_str_const ("NONE");
	sym->bind = r_str_const ("GLOBAL");
	sym->type = r_str_const ("OBJECT");
	r_list_append (syscalls, sym);

	i = 1;
	cursor += 24;
	int num_syscalls = sdb_count (syscall->db);
	while (cursor < end && i < num_syscalls) {
		ut64 addr = r_read_le64 (cursor);
		RSyscallItem * item = r_syscall_get (syscall, i, 0x80);
		if (item && item->name) {
			RBinSymbol * sym = R_NEW0 (RBinSymbol);
			if (!sym) {
				goto beach;
			}

			sym->name = r_str_newf ("syscall.%d.%s", i, item->name);
			sym->vaddr = addr;
			sym->paddr = addr;
			sym->size = 0;
			sym->forwarder = r_str_const ("NONE");
			sym->bind = r_str_const ("GLOBAL");
			sym->type = r_str_const ("FUNC");
			r_list_append (syscalls, sym);

			r_syscall_item_free (item);
		}

		cursor += 24;
		i++;
	}

	r_syscall_free (syscall);
	R_FREE (data_const);
	R_FREE (sections);
	return syscalls;

beach:
	r_syscall_free (syscall);
	R_FREE (syscalls);
	R_FREE (data_const);
	R_FREE (sections);
	return NULL;
}

static ut64 extract_addr_from_code(ut8 * arm64_code, ut64 vaddr) {
	ut64 addr = vaddr & ~0xfff;

	ut64 adrp = r_read_le32 (arm64_code);
	ut64 adrp_offset = ((adrp & 0x60000000) >> 29) | ((adrp & 0xffffe0) >> 3);
	addr += adrp_offset << 12;

	ut64 ldr = r_read_le32 (arm64_code + 4);
	addr += ((ldr & 0x3ffc00) >> 10) << ((ldr & 0xc0000000) >> 30);

	return addr;
}

static void symbols_from_stubs(RList *ret, SdbHash *kernel_syms_by_addr, RKernelCacheObj * obj, RBinFile *bf, RKext * kext, int ordinal) {
	RStubsInfo * stubs_info = get_stubs_info(kext->mach0, kext->range.offset);
	if (!stubs_info) {
		return;
	}
	ut64 stubs_cursor = stubs_info->stubs.offset;
	ut64 stubs_end = stubs_cursor + stubs_info->stubs.size;

	for (; stubs_cursor < stubs_end; stubs_cursor += 12) {
		ut8 arm64_code[8];
		if (r_buf_read_at (obj->cache_buf, stubs_cursor, arm64_code, 8) < 8) {
			break;
		}

		ut64 vaddr = stubs_cursor + obj->pa2va_exec;
		ut64 addr_in_got = extract_addr_from_code (arm64_code, vaddr);

		bool found = false;
		int level = 3;
		const char * name;

		ut64 target_addr = UT64_MAX;

		while (!found && level-- > 0) {
			ut64 offset_in_got = addr_in_got - obj->pa2va_exec;
			ut64 addr;
			if (r_buf_read_at (obj->cache_buf, offset_in_got, (ut8*) &addr, 8) < 8) {
				break;
			}

			if (level == 2) {
				target_addr = addr;
			}

			const char *key = sdb_fmt ("%"PFMT64x, addr);
			const char * name = sdb_ht_find (kernel_syms_by_addr, key, &found);

			if (found) {
				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				if (!sym) {
					break;
				}
				//sym->name = r_str_newf ("stub.%s.%s", KEXT_SHORT_NAME (kext), name);
				sym->name = r_str_newf ("stub.%s", name);
				sym->vaddr = vaddr;
				sym->paddr = stubs_cursor;
				sym->size = 12;
				sym->forwarder = r_str_const ("NONE");
				sym->bind = r_str_const ("LOCAL");
				sym->type = r_str_const ("FUNC");
				sym->ordinal = ordinal ++;
				r_list_append (ret, sym);
				break;
			}

			addr_in_got = addr;
		}

		if (found || target_addr == UT64_MAX) {
			continue;
		}

		RKext * remote_kext = r_kext_index_vget (obj->kexts, target_addr);
		if (!remote_kext) {
			continue;
		}

		RBinSymbol *remote_sym = R_NEW0 (RBinSymbol);
		if (!remote_sym) {
			break;
		}

		remote_sym->name = r_str_newf ("exp.%s.0x%"PFMT64x, KEXT_SHORT_NAME (remote_kext), target_addr);
		remote_sym->vaddr = target_addr;
		remote_sym->paddr = target_addr - obj->pa2va_exec;
		remote_sym->size = 0;
		remote_sym->forwarder = r_str_const ("NONE");
		remote_sym->bind = r_str_const ("GLOBAL");
		remote_sym->type = r_str_const ("FUNC");
		remote_sym->ordinal = ordinal ++;
		r_list_append (ret, remote_sym);

		RBinSymbol *local_sym = R_NEW0 (RBinSymbol);
		if (!local_sym) {
			break;
		}

		local_sym->name = r_str_newf ("stub.%s.0x%"PFMT64x, KEXT_SHORT_NAME (remote_kext), target_addr);
		local_sym->vaddr = vaddr;
		local_sym->paddr = stubs_cursor;
		local_sym->size = 12;
		local_sym->forwarder = r_str_const ("NONE");
		local_sym->bind = r_str_const ("GLOBAL");
		local_sym->type = r_str_const ("FUNC");
		local_sym->ordinal = ordinal ++;
		r_list_append (ret, local_sym);
	}
}

static RStubsInfo *get_stubs_info(struct MACH0_(obj_t) * mach0, ut64 paddr) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (mach0))) {
		return NULL;
	}

	RStubsInfo * stubs_info = R_NEW0 (RStubsInfo);
	if (!stubs_info) {
		return NULL;
	}

	int incomplete = 2;
	int i = 0;
	for (; !sections[i].last; i++) {
		if (strstr (sections[i].name, "__DATA_CONST.__got")) {
			stubs_info->got.offset = sections[i].offset + paddr;
			stubs_info->got.size = sections[i].size;
			stubs_info->got_addr = sections[i].addr;
			if (!--incomplete) {
				break;
			}
		}

		if (strstr (sections[i].name, "__TEXT_EXEC.__stubs")) {
			stubs_info->stubs.offset = sections[i].offset + paddr;
			stubs_info->stubs.size = sections[i].size;
			if (!--incomplete) {
				break;
			}
		}
	}

	R_FREE (sections);

	if (incomplete) {
		R_FREE (stubs_info);
	}

	return stubs_info;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	bool big_endian = 0;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("kernelcache");
	ret->rclass = strdup ("ios");
	ret->os = strdup ("iOS");
	ret->arch = strdup ("arm"); // XXX
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("xnu");
	ret->type = strdup ("kernel-cache");
	ret->bits = 64;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return 8LL;
	}

	RKernelCacheObj * obj = (RKernelCacheObj*) bf->o->bin_obj;
	return MACH0_(get_baddr)(obj->mach0);
}

static int destroy(RBinFile *bf) {
	r_kernel_cache_free ((RKernelCacheObj*) bf->o->bin_obj);
	return true;
}

static void r_kernel_cache_free(RKernelCacheObj * obj) {
	if (!obj) {
		return;
	}

	if (obj->mach0) {
		MACH0_(mach0_free) (obj->mach0);
		obj->mach0 = NULL;
		obj->cache_buf = NULL;
	}

	if (obj->cache_buf) {
		r_buf_free (obj->cache_buf);
		obj->cache_buf = NULL;
	}

	if (obj->prelink_info) {
		r_cf_value_dict_free (obj->prelink_info);
		obj->prelink_info = NULL;
	}

	if (obj->kexts) {
		r_kext_index_free (obj->kexts);
		obj->kexts = NULL;
	}

	R_FREE (obj);
}

RBinPlugin r_bin_plugin_kernelcache = {
	.name = "kernelcache",
	.desc = "kernelcache bin plugin",
	.license = "LGPL3",
	.destroy = &destroy,
	.load_bytes = &load_bytes,
	.load_buffer = &load_buffer,
	.entries = &entries,
	.baddr = &baddr,
	.symbols = &symbols,
	.sections = &sections,
	.check_bytes = &check_bytes,
	.info = &info
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_kernelcache,
	.version = R2_VERSION
};
#endif
