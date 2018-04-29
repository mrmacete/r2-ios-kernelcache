/* radare2 - LGPL - Copyright 2018 - mrmacete */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
// #include "../format/mach0/mach0_defines.h"
#define R_BIN_MACH064 1
#include "format/mach0/mach0.h"

#include "r_cf_dict.h"

typedef struct _RKernelCacheObj {
	RBuffer * cache_buf;
	RCFValueDict * prelink_info;
	ut64 pa2va_exec;
	ut64 pa2va_data;
	RList * kexts;
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
	char * name;
	ut64 mod_info;
	struct MACH0_(obj_t) * mach0;
} RKext;

static RPrelinkRange *get_prelink_info_range(const ut8 *header_bytes, ut64 length);
static RPrelinkRange *get_prelink_info_range_from_mach0(struct MACH0_(obj_t) * mach0);
static RList * filter_kexts(RKernelCacheObj * obj);

static void sections_from_mach0(RList * ret, struct MACH0_(obj_t) * mach0, RBinFile *bf, ut64 paddr, char * prefix);
static void handle_data_sections(RBinSection *sect);
static void symbols_from_mach0(RList *ret, struct MACH0_(obj_t) * mach0, RBinFile *bf, ut64 paddr, int ordinal);
static void symbols_from_stubs(RList *ret, SdbHash *kernel_syms_by_addr, RKernelCacheObj * obj, RBinFile *bf, RKext * kext, int ordinal);
static RStubsInfo *get_stubs_info(struct MACH0_(obj_t) * mach0, ut64 paddr);

static void r_kext_free(RKext * kext);
static struct MACH0_(obj_t) * create_kext_mach0(RKernelCacheObj * obj, RKext * kext);

static void process_constructors(RKernelCacheObj *obj, struct MACH0_(obj_t) *mach0, RList *ret, ut64 paddr, bool is_first);
static RBinAddr* newEntry(ut64 haddr, ut64 vaddr, int type);

static void r_kernel_cache_free(RKernelCacheObj * obj);

static void *load_buffer(RBinFile *bf, RBuffer *buf, ut64 loadaddr, Sdb * sdb) {
	RBuffer *fbuf = r_buf_new_with_io (&bf->rbin->iob, bf->fd);
	struct MACH0_(obj_t) *main_mach0 = MACH0_(new_buf_steal) (fbuf, bf->rbin->verbose);
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

	obj->kexts = kexts;

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
					kext->range.offset = ((RCFValueInteger*) item->value)->value;
					kext->range.offset -= obj->pa2va_exec;
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

		kext->mach0 = create_kext_mach0 (obj, kext);
		if (!kext->mach0) {
			r_kext_free (kext);
			continue;
		}

		r_list_push (kexts, kext);
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

static struct MACH0_(obj_t) * create_kext_mach0(RKernelCacheObj * obj, RKext * kext) {
	int sz = 1024 * 1024 * 2;

	ut8 * bytes = malloc (sz);
	if (!bytes) {
		return NULL;
	}

	sz = r_buf_read_at (obj->cache_buf, kext->range.offset, bytes, sz);

	RBuffer *buf = r_buf_new ();
	r_buf_set_bytes_steal (buf, bytes, sz);
	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf_steal) (buf, true);
	if (!mach0) {
		r_buf_free (buf);
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

	process_constructors (kobj, kobj->mach0, ret, 0, true);

/*	RListIter * iter;
	RKext * kext;
	r_list_foreach (kobj->kexts, iter, kext) {
		process_constructors (kobj, kext->mach0, ret, kext->range.offset, false);
	}*/

	return ret;
}

static void process_constructors(RKernelCacheObj *obj, struct MACH0_(obj_t) *mach0, RList *ret, ut64 paddr, bool is_first) {
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
		for (j = 0; j < sections[i].size; j += 8) {
			ut64 addr64 = r_read_le64 (buf + j);
			RBinAddr *ba = newEntry (sections[i].offset + paddr + j, addr64, type);
			r_list_append (ret, ba);
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
	ptr->haddr = haddr;
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

	sections_from_mach0 (ret, kobj->mach0, bf, 0, NULL);

	RListIter * iter;
	RKext * kext;
	r_list_foreach (kobj->kexts, iter, kext) {
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

	return ret;
}

static void sections_from_mach0(RList * ret, struct MACH0_(obj_t) * mach0, RBinFile *bf, ut64 paddr, char * prefix) {
	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections) (mach0))) {
		return;
	}
	int i;
	for (i = 0; !sections[i].last; i++) {
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
	r_list_foreach (ret, iter, sym) {
		const char *key = sdb_fmt ("%"PFMT64x, sym->vaddr);
		sdb_ht_insert (kernel_syms_by_addr, key, sym->dname ? sym->dname : sym->name);
	}

	RKext * kext;
	r_list_foreach (obj->kexts, iter, kext) {
		ut8 magicbytes[4];
		r_buf_read_at (obj->cache_buf, kext->range.offset, magicbytes, 4);
		int magic = r_read_le32 (magicbytes);
		switch (magic) {
		case MH_MAGIC_64:
			symbols_from_mach0 (ret, kext->mach0, bf, kext->range.offset, r_list_length (ret));
			symbols_from_stubs (ret, kernel_syms_by_addr, obj, bf, kext, r_list_length (ret));
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

static ut64 extract_addr_from_code(ut8 * arm64_code, ut64 vaddr) {
	ut64 addr = vaddr & ~0xfff;

	ut64 adrp = r_read_le32 (arm64_code);
	ut64 adrp_offset = ((adrp & 0x60000000) >> 29) | ((adrp & 0xffffe0) >> 3);
	addr += adrp_offset << 12;

	ut64 ldr = r_read_le32 (arm64_code + 4);
	addr += ((ldr & 0x3ffc00) >> 10) << ((ldr & 0xc0000000) >> 30);

	return addr;
}


#define KEXT_SHORT_NAME(kext) ({\
	const char * sn = strrchr (kext->name, '.');\
	sn ? sn + 1 : kext->name;\
})

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

		while (!found && level-- > 0) {
			ut64 offset_in_got = addr_in_got - obj->pa2va_exec;
			ut64 addr;
			if (r_buf_read_at (obj->cache_buf, offset_in_got, (ut8*) &addr, 8) < 8) {
				break;
			}

			const char *key = sdb_fmt ("%"PFMT64x, addr);
			const char * name = sdb_ht_find (kernel_syms_by_addr, key, &found);

			if (found) {
				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				if (!sym) {
					break;
				}
				sym->name = r_str_newf ("stub.%s.%s", KEXT_SHORT_NAME (kext), name);
				sym->vaddr = vaddr;
				sym->paddr = stubs_cursor;
				sym->size = 12;
				sym->ordinal = ordinal ++;
				r_list_append (ret, sym);
				break;
			}

			addr_in_got = addr;
		}
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
		r_list_free (obj->kexts);
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
