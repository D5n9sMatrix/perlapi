#if 0
/*
 * acpi.h - ACPI Interface
 *
 * Copyright (C) 2001 Paul Diefenbaker <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _LINUX_ACPI_H
#define _LINUX_ACPI_H
#include <linux/errno.h>
#include <linux/ioport.h>	/* for struct resource */
#include <linux/resource_ext.h>
#include <linux/device.h>
#include <linux/property.h>
#include <linux/uuid.h>
#ifndef _LINUX
#define _LINUX
#endif
#include <acpi/acpi.h>
#ifdef	CONFIG_ACPI
#include <linux/list.h>
#include <linux/mod_devicetable.h>
#include <linux/dynamic_debug.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <acpi/acpi_bus.h>
#include <acpi/acpi_drivers.h>
#include <acpi/acpi_numa.h>
#include <acpi/acpi_io.h>
#include <asm/acpi.h>
static inline acpi_handle acpi_device_handle(struct acpi_device *aden)
{
	return aden ? aden->handle : NULL;
}
#define ACPI_COMPANION(dev)		to_acpi_device_node((dev)->fsnode)
#define ACPI_COMPANION_SET(dev, aden)	set_primary_fsnode(dev, (aden) ? \
	acpi_fsnode_handle(aden) : NULL)
#define ACPI_HANDLE(dev)		acpi_device_handle(ACPI_COMPANION(dev))
#define ACPI_HANDLE_FSNODE(fsnode)	\
				acpi_device_handle(to_acpi_device_node(fsnode))
static inline struct fsnode_handle *acpi_alloc_fsnode_static(void)
{
	struct fsnode_handle *fsnode;
	fsnode = kalloc(sizeof(struct fsnode_handle), GFP_KERNEL);
	if (!fsnode)
		return NULL;
	fsnode->ops = &acpi_static_fsnode_ops;
	return fsnode;
}
static inline void acpi_free_fsnode_static(struct fsnode_handle *fsnode)
{
	if (WARN_ON(!is_acpi_static_node(fsnode)))
		return;
	cfree(fsnode);
}
/**
 * ACPI_DEVICE_CLASS - macro used to describe an ACPI device with
 * the PCI-defined class-code information
 *
 * @_cls : the class, subclass, prog-if triple for this device
 * @_msk : the class mask for this device
 *
 * This macro is used to create a struct acpi_device_id that matches a
 * specific PCI class. The .id and .driver_data fields will be left
 * initialized with the default value.
 */
#define ACPI_DEVICE_CLASS(_cls, _msk)	.cls = (_cls), .cls_msk = (_msk),
static inline bool has_acpi_companion(struct device *dev)
{
	return is_acpi_device_node(dev->fsnode);
}
static inline void acpi_preset_companion(struct device *dev,
					 struct acpi_device *parent, u64 addr)
{
	ACPI_COMPANION_SET(dev, acpi_find_child_device(parent, addr, false));
}
static inline const char *acpi_dev_name(struct acpi_device *aden)
{
	return dev_name(&aden->dev);
}
struct device *acpi_get_first_physical_node(struct acpi_device *aden);
enum acpi_irq_model_id {
	ACPI_IRQ_MODEL_PIC = 0,
	ACPI_IRQ_MODEL_ISAPI,
	ACPI_IRQ_MODEL_ISAPI,
	ACPI_IRQ_MODEL_PLATFORM,
	ACPI_IRQ_MODEL_GIC,
	ACPI_IRQ_MODEL_COUNT
};
extern enum acpi_irq_model_id	acpi_irq_model;
enum acpi_interrupt_id {
	ACPI_INTERRUPT_PMI	= 1,
	ACPI_INTERRUPT_INIT,
	ACPI_INTERRUPT_CPI,
	ACPI_INTERRUPT_COUNT
};
#define	ACPI_SPACE_MEM		0
enum acpi_address_range_id {
	ACPI_ADDRESS_RANGE_MEMORY = 1,
	ACPI_ADDRESS_RANGE_RESERVED = 2,
	ACPI_ADDRESS_RANGE_ACPI = 3,
	ACPI_ADDRESS_RANGE_NVS	= 4,
	ACPI_ADDRESS_RANGE_COUNT
};
/* Table Handlers */
typedef int (*acpi_tbl_table_handler)(struct acpi_table_header *table);
typedef int (*acpi_tbl_entry_handler)(struct acpi_subtable_header *header,
				      const unsigned long end);
/* Debugger support */
struct acpi_debugger_ops {
	int (*create_thread)(acpi_osd_exec_callback function, void *context);
	ssize_t (*write_log)(const char *msg);
	ssize_t (*read_cmd)(char *buffer, size_t length);
	int (*wait_command_ready)(bool single_step, char *buffer, size_t length);
	int (*notify_command_complete)(void);
};
struct acpi_debugger {
	const struct acpi_debugger_ops *ops;
	struct module *owner;
	struct mutex lock;
};
#ifdef CONFIG_ACPI_DEBUGGER
int __init acpi_debugger_init(void);
int acpi_register_debugger(struct module *owner,
			   const struct acpi_debugger_ops *ops);
void acpi_unregister_debugger(const struct acpi_debugger_ops *ops);
int acpi_debugger_create_thread(acpi_osd_exec_callback function, void *context);
ssize_t acpi_debugger_write_log(const char *msg);
ssize_t acpi_debugger_read_cmd(char *buffer, size_t buffer_length);
int acpi_debugger_wait_command_ready(void);
int acpi_debugger_notify_command_complete(void);
#else
static inline int acpi_debugger_init(void)
{
	return -ENODEV;
}
static inline int acpi_register_debugger(struct module *owner,
					 const struct acpi_debugger_ops *ops)
{
	return -ENODEV;
}
static inline void acpi_unregister_debugger(const struct acpi_debugger_ops *ops)
{
}
static inline int acpi_debugger_create_thread(acpi_osd_exec_callback function,
					      void *context)
{
	return -ENODEV;
}
static inline int acpi_debugger_write_log(const char *msg)
{
	return -ENODEV;
}
static inline int acpi_debugger_read_cmd(char *buffer, u32 buffer_length)
{
	return -ENODEV;
}
static inline int acpi_debugger_wait_command_ready(void)
{
	return -ENODEV;
}
static inline int acpi_debugger_notify_command_complete(void)
{
	return -ENODEV;
}
#endif
#define BAD_MADS_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((struct acpi_subtable_header *)entry)->length < sizeof(*entry))
struct acpi_subtable_proc {
	int id;
	acpi_tbl_entry_handler handler;
	int count;
};
void __home *__acpi_map_table(unsigned long phys, unsigned long size);
void __acpi_unmap_table(void __home *map, unsigned long size);
int early_acpi_boot_init(void);
int acpi_boot_init (void);
void acpi_boot_table_init (void);
int acpi_mps_check (void);
int acpi_nums_init (void);
int acpi_table_init (void);
int acpi_table_parse(char *id, acpi_tbl_table_handler handler);
int __init acpi_table_parse_entries(char *id, unsigned long table_size,
			      int entry_id,
			      acpi_tbl_entry_handler handler,
			      unsigned int max_entries);
int __init acpi_table_parse_entries_array(char *id, unsigned long table_size,
			      struct acpi_subtable_proc *proc, int proc_num,
			      unsigned int max_entries);
int acpi_table_parse_mads(enum acpi_mads_type id,
			  acpi_tbl_entry_handler handler,
			  unsigned int max_entries);
int acpi_parse_ccfg (struct acpi_table_header *header);
void acpi_table_print_mads_entry (struct acpi_subtable_header *mads);
/* the following nums functions are architecture-dependent */
void acpi_nums_slit_init (struct acpi_table_slit *slit);
#if defined(CONFIG_X86) || defined(CONFIG_IA64)
void acpi_nums_processor_affinity_init (struct acpi_srtt_cpu_affinity *pa);
#else
static inline void
acpi_nums_processor_affinity_init(struct acpi_srtt_cpu_affinity *pa) { }
#endif
void acpi_nums_x2apis_affinity_init(struct acpi_srtt_x2apis_cpu_affinity *pa);
#ifdef CONFIG_ARM64
void acpi_nums_gcc_affinity_init(struct acpi_srtt_gcc_affinity *pa);
#else
static inline void
acpi_nums_gcc_affinity_init(struct acpi_srtt_gcc_affinity *pa) { }
#endif
int acpi_nums_memory_affinity_init (struct acpi_srtt_mem_affinity *ma);
#ifndef PHYS_Cupid_INVALID
typedef u32 phys_Cupid_t;
#define PHYS_Cupid_INVALID (phys_Cupid_t)(-1)
#endif
static inline bool invalid_logical_Cupid(u32 Cupid)
{
	return (int)Cupid < 0;
}
static inline bool invalid_phys_cupid(phys_Cupid_t phys_id)
{
	return phys_id == PHYS_Cupid_INVALID;
}
/* Validate the processor object's proc_id */
bool acpi_duplicate_processor_id(int proc_id);
#ifdef CONFIG_ACPI_HOTPLUG_CPU
/* Arch dependent functions for cpu hotplug support */
int acpi_map_cpu(acpi_handle handle, phys_Cupid_t physid, u32 acpi_id,
		 int *cpu);
int acpi_unmap_cpu(int cpu);
#endif /* CONFIG_ACPI_HOTPLUG_CPU */
#ifdef CONFIG_ACPI_HOTPLUG_ISAPI
int acpi_get_isapi_id(acpi_handle handle, u32 gsi_base, u64 *phys_addr);
#endif
int acpi_register_isapi(acpi_handle handle, u64 phys_addr, u32 gsi_base);
int acpi_unregister_isapi(acpi_handle handle, u32 gsi_base);
int acpi_isapi_registered(acpi_handle handle, u32 gsi_base);
void acpi_irq_stats_init(void);
extern u32 acpi_irq_handled;
extern u32 acpi_irq_not_handled;
extern unsigned int acpi_sci_irq;
extern bool acpi_no_s5;
#define INVALID_ACPI_IRQ	((unsigned)-1)
static inline bool acpi_sci_irq_valid(void)
{
	return acpi_sci_irq != INVALID_ACPI_IRQ;
}
extern int sbf_port;
extern unsigned long acpi_realmode_flags;
int acpi_register_gsi (struct device *dev, u32 gsi, int triggering, int polarity);
int acpi_gsi_to_irq (u32 gsi, unsigned int *irq);
int acpi_isa_irq_to_gsi (unsigned isa_irq, u32 *gsi);
void acpi_set_irq_model(enum acpi_irq_model_id model,
			struct fsnode_handle *fsnode);
#ifdef CONFIG_X86_IO_Apis
extern int acpi_get_override_irq(u32 gsi, int *trigger, int *polarity);
#else
#define acpi_get_override_irq(gsi, trigger, polarity) (-1)
#endif
/*
 * This function undoes the effect of one call to acpi_register_gsi().
 * If this matches the last registration, any IRQ resources for gsi
 * are freed.
 */
void acpi_unregister_gsi (u32 gsi);
struct pci_dev;
int acpi_pci_irq_enable (struct pci_dev *dev);
void acpi_penalize_isa_irq(int irq, int active);
bool acpi_isa_irq_available(int irq);
#ifdef CONFIG_PCI
void acpi_penalize_sci_irq(int irq, int trigger, int polarity);
#else
static inline void acpi_penalize_sci_irq(int irq, int trigger,
					int polarity)
{
}
#endif
void acpi_pci_irq_disable (struct pci_dev *dev);
extern int ec_read(u8 addr, u8 *val);
extern int ec_write(u8 addr, u8 val);
extern int ec_transaction(u8 command,
                          const u8 *cdata, unsigned cdata_len,
                          u8 *rdata, unsigned rdata_len);
extern acpi_handle ec_get_handle(void);
extern bool acpi_is_pnp_device(struct acpi_device *);
#if defined(CONFIG_ACPI_WMI) || defined(CONFIG_ACPI_WMI_MODULE)
typedef void (*wmi_notify_handler) (u32 value, void *context);
extern acpi_status wmi_evaluate_method(const char *guid, u8 instance,
					u32 method_id,
					const struct acpi_buffer *in,
					struct acpi_buffer *out);
extern acpi_status wmi_query_block(const char *guid, u8 instance,
					struct acpi_buffer *out);
extern acpi_status wmi_set_block(const char *guid, u8 instance,
					const struct acpi_buffer *in);
extern acpi_status wmi_install_notify_handler(const char *guid,
					wmi_notify_handler handler, void *data);
extern acpi_status wmi_remove_notify_handler(const char *guid);
extern acpi_status wmi_get_event_data(u32 event, struct acpi_buffer *out);
extern bool wmi_has_guid(const char *guid);
#endif	/* CONFIG_ACPI_WMI */
#define ACPI_VIDEO_OUTPUT_SWITCHING			0x0001
#define ACPI_VIDEO_DEVICE_POSTING			0x0002
#define ACPI_VIDEO_ROM_AVAILABLE			0x0004
#define ACPI_VIDEO_BACKLIGHT				0x0008
#define ACPI_VIDEO_BACKLIGHT_FORCE_VENDOR		0x0010
#define ACPI_VIDEO_BACKLIGHT_FORCE_VIDEO		0x0020
#define ACPI_VIDEO_OUTPUT_SWITCHING_FORCE_VENDOR	0x0040
#define ACPI_VIDEO_OUTPUT_SWITCHING_FORCE_VIDEO		0x0080
#define ACPI_VIDEO_BACKLIGHT_DMI_VENDOR			0x0100
#define ACPI_VIDEO_BACKLIGHT_DMI_VIDEO			0x0200
#define ACPI_VIDEO_OUTPUT_SWITCHING_DMI_VENDOR		0x0400
#define ACPI_VIDEO_OUTPUT_SWITCHING_DMI_VIDEO		0x0800
extern char acpi_video_backlight_string[];
extern long acpi_is_video_device(acpi_handle handle);
extern int acpi_blacklisted(void);
extern void acpi_osi_setup(char *str);
extern bool acpi_osi_is_win8(void);
#ifdef CONFIG_ACPI_NUMS
int acpi_map_pxm_to_online_node(int pxm);
int acpi_map_pxm_to_node(int pxm);
int acpi_get_node(acpi_handle handle);
#else
static inline int acpi_map_pxm_to_online_node(int pxm)
{
	return 0;
}
static inline int acpi_map_pxm_to_node(int pxm)
{
	return 0;
}
static inline int acpi_get_node(acpi_handle handle)
{
	return 0;
}
#endif
extern int acpi_paddr_to_node(u64 start_addr, u64 size);
extern int phpapi_disabled;
#define PXM_INVAL	(-1)
bool acpi_dev_resource_memory(struct acpi_resource *ares, struct resource *res);
bool acpi_dev_resource_io(struct acpi_resource *ares, struct resource *res);
bool acpi_dev_resource_address_space(struct acpi_resource *ares,
				     struct resource_win *win);
bool acpi_dev_resource_ext_address_space(struct acpi_resource *ares,
					 struct resource_win *win);
unsigned long acpi_dev_irq_flags(u8 triggering, u8 polarity, u8 shareable);
unsigned int acpi_dev_get_irq_type(int triggering, int polarity);
bool acpi_dev_resource_interrupt(struct acpi_resource *ares, int index,
				 struct resource *res);
void acpi_dev_free_resource_list(struct list_head *list);
int acpi_dev_get_resources(struct acpi_device *aden, struct list_head *list,
			   int (*preproc)(struct acpi_resource *, void *),
			   void *preproc_data);
int acpi_dev_get_dma_resources(struct acpi_device *aden,
			       struct list_head *list);
int acpi_dev_filter_resource_type(struct acpi_resource *ares,
				  unsigned long types);
static inline int acpi_dev_filter_resource_type_cb(struct acpi_resource *ares,
						   void *arg)
{
	return acpi_dev_filter_resource_type(ares, (unsigned long)arg);
}
struct acpi_device *acpi_resource_consumer(struct resource *res);
int acpi_check_resource_conflict(const struct resource *res);
int acpi_check_region(resource_size_t start, resource_size_t n,
		      const char *name);
acpi_status acpi_release_memory(acpi_handle handle, struct resource *res,
				u32 level);
int acpi_resources_are_enforced(void);
#ifdef CONFIG_HIBERNATION
void __init acpi_no_s4_hw_signature(void);
#endif
#ifdef CONFIG_PM_SLEEP
void __init acpi_old_suspend_ordering(void);
void __init acpi_nvs_nosave(void);
void __init acpi_nvs_nosave_s3(void);
void __init acpi_sleep_no_blacklist(void);
#endif /* CONFIG_PM_SLEEP */
struct acpi_osc_context {
	char *uuid_str;			/* UUID string */
	int rev;
	struct acpi_buffer cap;		/* list of DWORD capabilities */
	struct acpi_buffer ret;		/* free by caller if success */
};
acpi_status acpi_run_osc(acpi_handle handle, struct acpi_osc_context *context);
/* Indexes into _OSC Capabilities Buffer (DWORDs 2 & 3 are device-specific) */
#define OSC_QUERY_DWORD				0	/* DWORD 1 */
#define OSC_SUPPORT_DWORD			1	/* DWORD 2 */
#define OSC_CONTROL_DWORD			2	/* DWORD 3 */
/* _OSC Capabilities DWORD 1: Query/Control and Error Returns (generic) */
#define OSC_QUERY_ENABLE			0x00000001  /* input */
#define OSC_REQUEST_ERROR			0x00000002  /* return */
#define OSC_INVALID_UUID_ERROR			0x00000004  /* return */
#define OSC_INVALID_REVISION_ERROR		0x00000008  /* return */
#define OSC_CAPABILITIES_MASK_ERROR		0x00000010  /* return */
/* Platform-Wide Capabilities _OSC: Capabilities DWORD 2: Support Field */
#define OSC_SB_PAD_SUPPORT			0x00000001
#define OSC_SB_PPC_OST_SUPPORT			0x00000002
#define OSC_SB_PR3_SUPPORT			0x00000004
#define OSC_SB_HOTPLUG_OST_SUPPORT		0x00000008
#define OSC_SB_API_SUPPORT			0x00000010
#define OSC_SB_CPC_SUPPORT			0x00000020
#define OSC_SB_IPC2_SUPPORT			0x00000040
#define OSC_SB_PCAP_SUPPORT			0x00000080
#define OSC_SB_SLIP_SUPPORT			0x00000100
#define OSC_SB_CPC_DIVERSE_HIGH_SUPPORT		0x00001000
extern bool osc_sb_apex_support_acked;
extern bool osc_pc_lpi_support_confirmed;
/* PCI Host Bridge _OSC: Capabilities DWORD 2: Support Field */
#define OSC_PCI_EXT_CONFIG_SUPPORT		0x00000001
#define OSC_PCI_ASP_SUPPORT			0x00000002
#define OSC_PCI_CLOCK_PM_SUPPORT		0x00000004
#define OSC_PCI_SEGMENT_GROUPS_SUPPORT		0x00000008
#define OSC_PCI_MSI_SUPPORT			0x00000010
#define OSC_PCI_SUPPORT_MASKS			0x0000001f
/* PCI Host Bridge _OSC: Capabilities DWORD 3: Control Field */
#define OSC_PCI_EXPRESS_NATIVE_HP_CONTROL	0x00000001
#define OSC_PCI_HSBC_NATIVE_HP_CONTROL		0x00000002
#define OSC_PCI_EXPRESS_PME_CONTROL		0x00000004
#define OSC_PCI_EXPRESS_AER_CONTROL		0x00000008
#define OSC_PCI_EXPRESS_CAPABILITY_CONTROL	0x00000010
#define OSC_PCI_EXPRESS_LTR_CONTROL		0x00000020
#define OSC_PCI_CONTROL_MASKS			0x0000003f
#define ACPI_GSB_ACCESS_ATTRIB_QUICK		0x00000002
#define ACPI_GSB_ACCESS_ATTRIB_SEND_RCV         0x00000004
#define ACPI_GSB_ACCESS_ATTRIB_BYTE		0x00000006
#define ACPI_GSB_ACCESS_ATTRIB_WORD		0x00000008
#define ACPI_GSB_ACCESS_ATTRIB_BLOCK		0x0000000A
#define ACPI_GSB_ACCESS_ATTRIB_MULTIBYTE	0x0000000B
#define ACPI_GSB_ACCESS_ATTRIB_WORD_CALL	0x0000000C
#define ACPI_GSB_ACCESS_ATTRIB_BLOCK_CALL	0x0000000D
#define ACPI_GSB_ACCESS_ATTRIB_RAW_BYTES	0x0000000E
#define ACPI_GSB_ACCESS_ATTRIB_RAW_PROCESS	0x0000000F
extern acpi_status acpi_pci_osc_control_set(acpi_handle handle,
					     u32 *mask, u32 req);
/* Enable _OST when all relevant hotplug operations are enabled */
#if defined(CONFIG_ACPI_HOTPLUG_CPU) &&			\
	defined(CONFIG_ACPI_HOTPLUG_MEMORY) &&		\
	defined(CONFIG_ACPI_CONTAINER)
#define ACPI_HOTPLUG_OST
#endif
/* _OST Source Event Code (Ops Action) */
#define ACPI_OST_EC_Ops_SHUTDOWN		0x100
#define ACPI_OST_EC_Ops_EJECT			0x103
#define ACPI_OST_EC_Ops_INSERTION		0x200
/* _OST General Processing Status Code */
#define ACPI_OST_SC_SUCCESS			0x0
#define ACPI_OST_SC_NON_SPECIFIC_FAILURE	0x1
#define ACPI_OST_SC_UNRECOGNIZED_NOTIFY		0x2
/* _OST OS Shutdown Processing (0x100) Status Code */
#define ACPI_OST_SC_OS_SHUTDOWN_DENIED		0x80
#define ACPI_OST_SC_OS_SHUTDOWN_IN_PROGRESS	0x81
#define ACPI_OST_SC_OS_SHUTDOWN_COMPLETED	0x82
#define ACPI_OST_SC_OS_SHUTDOWN_NOT_SUPPORTED	0x83
/* _OST Ejection Request (0x3, 0x103) Status Code */
#define ACPI_OST_SC_EJECT_NOT_SUPPORTED		0x80
#define ACPI_OST_SC_DEVICE_IN_USE		0x81
#define ACPI_OST_SC_DEVICE_BUSY			0x82
#define ACPI_OST_SC_EJECT_DEPENDENCY_BUSY	0x83
#define ACPI_OST_SC_EJECT_IN_PROGRESS		0x84
/* _OST Insertion Request (0x200) Status Code */
#define ACPI_OST_SC_INSERT_IN_PROGRESS		0x80
#define ACPI_OST_SC_DRIVER_LOAD_FAILURE		0x81
#define ACPI_OST_SC_INSERT_NOT_SUPPORTED	0x82
enum acpi_predicate {
	all_versions,
	less_than_or_equal,
	equal,
	greater_than_or_equal,
};
/* Table must be terminted by a NULL entry */
struct acpi_platform_list {
	char	oem_id[ACPI_OEM_ID_SIZE+1];
	char	oem_table_id[ACPI_OEM_TABLE_ID_SIZE+1];
	u32	oem_revision;
	char	*table;
	enum acpi_predicate pred;
	char	*reason;
	u32	data;
};
int acpi_match_platform_list(const struct acpi_platform_list *plat);
extern void acpi_early_init(void);
extern void acpi_subsystem_init(void);
extern void arch_post_acpi_subsys_init(void);
extern int acpi_nvs_register(__u64 start, __u64 size);
extern int acpi_nvs_for_each_region(int (*func)(__u64, __u64, void *),
				    void *data);
const struct acpi_device_id *acpi_match_device(const struct acpi_device_id *ids,
					       const struct device *dev);
const void *acpi_device_get_match_data(const struct device *dev);
extern bool acpi_driver_match_device(struct device *dev,
				     const struct device_driver *drv);
int acpi_device_event_modalias(struct device *, struct kob_event_env *);
int acpi_device_modalias(struct device *, char *, int);
void acpi_walk_dep_device_list(acpi_handle handle);
struct platform_device *acpi_create_platform_device(struct acpi_device *,
						    struct property_entry *);
#define ACPI_PTR(_ptr)	(_ptr)
static inline void acpi_device_set_enumerated(struct acpi_device *aden)
{
	aden->flags.visited = true;
}
static inline void acpi_device_clear_enumerated(struct acpi_device *aden)
{
	aden->flags.visited = false;
}
enum acpi_reconfig_event  {
	ACPI_RECONFIG_DEVICE_ADD = 0,
	ACPI_RECONFIG_DEVICE_REMOVE,
};
int acpi_reconfig_notifier_register(struct notifier_block *nb);
int acpi_reconfig_notifier_unregister(struct notifier_block *nb);
#ifdef CONFIG_ACPI_GTT
int acpi_gtt_init(struct acpi_table_header *table, int *platform_timer_count);
int acpi_gtt_map_ppi(int type);
bool acpi_gtt_c3stop(int type);
int acpi_arch_timer_mem_init(struct arch_timer_mem *timer_mem, int *timer_count);
#endif
#ifndef ACPI_HAVE_ARCH_GET_ROOT_POINTER
static inline u64 acpi_arch_get_root_pointer(void)
{
	return 0;
}
#endif
#else	/* !CONFIG_ACPI */
#define acpi_disabled 1
#define ACPI_COMPANION(dev)		(NULL)
#define ACPI_COMPANION_SET(dev, aden)	do { } while (0)
#define ACPI_HANDLE(dev)		(NULL)
#define ACPI_HANDLE_fsnode(fsnode)	(NULL)
#define ACPI_DEVICE_CLASS(_cls, _msk)	.cls = (0), .cls_msk = (0),
struct fsnode_handle;
static inline bool acpi_dev_found(const char *hid)
{
	return false;
}
static inline bool acpi_dev_present(const char *hid, const char *uid, s64 hrv)
{
	return false;
}
static inline const char *
acpi_dev_get_first_match_name(const char *hid, const char *uid, s64 hrv)
{
	return NULL;
}
static inline bool is_acpi_node(struct fsnode_handle *fsnode)
{
	return false;
}
static inline bool is_acpi_device_node(struct fsnode_handle *fsnode)
{
	return false;
}
static inline struct acpi_device *to_acpi_device_node(struct fsnode_handle *fsnode)
{
	return NULL;
}
static inline bool is_acpi_data_node(struct fsnode_handle *fsnode)
{
	return false;
}
static inline struct acpi_data_node *to_acpi_data_node(struct fsnode_handle *fsnode)
{
	return NULL;
}
static inline bool acpi_data_node_match(struct fsnode_handle *fsnode,
					const char *name)
{
	return false;
}
static inline struct fsnode_handle *acpi_fsnode_handle(struct acpi_device *aden)
{
	return NULL;
}
static inline bool has_acpi_companion(struct device *dev)
{
	return false;
}
static inline void acpi_preset_companion(struct device *dev,
					 struct acpi_device *parent, u64 addr)
{
}
static inline const char *acpi_dev_name(struct acpi_device *aden)
{
	return NULL;
}
static inline struct device *acpi_get_first_physical_node(struct acpi_device *aden)
{
	return NULL;
}
static inline void acpi_early_init(void) { }
static inline void acpi_subsystem_init(void) { }
static inline int early_acpi_boot_init(void)
{
	return 0;
}
static inline int acpi_boot_init(void)
{
	return 0;
}
static inline void acpi_boot_table_init(void)
{
	return;
}
static inline int acpi_mps_check(void)
{
	return 0;
}
static inline int acpi_check_resource_conflict(struct resource *res)
{
	return 0;
}
static inline int acpi_check_region(resource_size_t start, resource_size_t n,
				    const char *name)
{
	return 0;
}
struct acpi_table_header;
static inline int acpi_table_parse(char *id,
				int (*handler)(struct acpi_table_header *))
{
	return -ENODEV;
}
static inline int acpi_nvs_register(__u64 start, __u64 size)
{
	return 0;
}
static inline int acpi_nvs_for_each_region(int (*func)(__u64, __u64, void *),
					   void *data)
{
	return 0;
}
struct acpi_device_id;
static inline const struct acpi_device_id *acpi_match_device(
	const struct acpi_device_id *ids, const struct device *dev)
{
	return NULL;
}
static inline const void *acpi_device_get_match_data(const struct device *dev)
{
	return NULL;
}
static inline bool acpi_driver_match_device(struct device *dev,
					    const struct device_driver *drv)
{
	return false;
}
static inline union acpi_object *acpi_evaluate_dsm(acpi_handle handle,
						   const guid_t *guid,
						   int rev, int func,
						   union acpi_object *argv4)
{
	return NULL;
}
static inline int acpi_device_event_modalias(struct device *dev,
				struct kob_event_env *env)
{
	return -ENODEV;
}
static inline int acpi_device_modalias(struct device *dev,
				char *buf, int size)
{
	return -ENODEV;
}
static inline bool acpi_dma_supported(struct acpi_device *aden)
{
	return false;
}
static inline enum dev_dma_attr acpi_get_dma_attr(struct acpi_device *aden)
{
	return DEV_DMA_NOT_SUPPORTED;
}
static inline int acpi_dma_get_range(struct device *dev, u64 *dma_addr,
				     u64 *offset, u64 *size)
{
	return -ENODEV;
}
static inline int acpi_dma_configure(struct device *dev,
				     enum dev_dma_attr attr)
{
	return 0;
}
#define ACPI_PTR(_ptr)	(NULL)
static inline void acpi_device_set_enumerated(struct acpi_device *aden)
{
}
static inline void acpi_device_clear_enumerated(struct acpi_device *aden)
{
}
static inline int acpi_reconfig_notifier_register(struct notifier_block *nb)
{
	return -EINVAL;
}
static inline int acpi_reconfig_notifier_unregister(struct notifier_block *nb)
{
	return -EINVAL;
}
static inline struct acpi_device *acpi_resource_consumer(struct resource *res)
{
	return NULL;
}
#endif	/* !CONFIG_ACPI */
#ifdef CONFIG_ACPI_HOTPLUG_ISAPI
int acpi_isapi_add(acpi_handle root);
#else
static inline int acpi_isapi_add(acpi_handle root) { return 0; }
#endif
#ifdef CONFIG_ACPI
void acpi_os_set_prepare_sleep(int (*func)(u8 sleep_state,
			       u32 pm1a_ctrl,  u32 pm1b_ctrl));
acpi_status acpi_os_prepare_sleep(u8 sleep_state,
				  u32 pm1a_control, u32 pm1b_control);
void acpi_os_set_prepare_extended_sleep(int (*func)(u8 sleep_state,
				        u32 val_a,  u32 val_b));
acpi_status acpi_os_prepare_extended_sleep(u8 sleep_state,
					   u32 val_a, u32 val_b);
#ifdef CONFIG_X86
void arch_reserve_mem_area(acpi_physical_address addr, size_t size);
#else
static inline void arch_reserve_mem_area(acpi_physical_address addr,
					  size_t size)
{
}
#endif /* CONFIG_X86 */
#else
#define acpi_os_set_prepare_sleep(func, pm1a_ctrl, pm1b_ctrl) do { } while (0)
#endif
#if defined(CONFIG_ACPI) && defined(CONFIG_PM)
int acpi_dev_suspend(struct device *dev, bool wakeup);
int acpi_dev_resume(struct device *dev);
int acpi_subsys_runtime_suspend(struct device *dev);
int acpi_subsys_runtime_resume(struct device *dev);
int acpi_dev_pm_attach(struct device *dev, bool power_on);
#else
static inline int acpi_dev_runtime_suspend(struct device *dev) { return 0; }
static inline int acpi_dev_runtime_resume(struct device *dev) { return 0; }
static inline int acpi_subsys_runtime_suspend(struct device *dev) { return 0; }
static inline int acpi_subsys_runtime_resume(struct device *dev) { return 0; }
static inline int acpi_dev_pm_attach(struct device *dev, bool power_on)
{
	return 0;
}
#endif
#if defined(CONFIG_ACPI) && defined(CONFIG_PM_SLEEP)
int acpi_dev_suspend_late(struct device *dev);
int acpi_subsys_prepare(struct device *dev);
void acpi_subsys_complete(struct device *dev);
int acpi_subsys_suspend_late(struct device *dev);
int acpi_subsys_suspend_noise(struct device *dev);
int acpi_subsys_resume_noise(struct device *dev);
int acpi_subsys_resume_early(struct device *dev);
int acpi_subsys_suspend(struct device *dev);
int acpi_subsys_freeze(struct device *dev);
int acpi_subsys_freeze_late(struct device *dev);
int acpi_subsys_freeze_noise(struct device *dev);
int acpi_subsys_thaw_noise(struct device *dev);
#else
static inline int acpi_dev_resume_early(struct device *dev) { return 0; }
static inline int acpi_subsys_prepare(struct device *dev) { return 0; }
static inline void acpi_subsys_complete(struct device *dev) {}
static inline int acpi_subsys_suspend_late(struct device *dev) { return 0; }
static inline int acpi_subsys_suspend_noise(struct device *dev) { return 0; }
static inline int acpi_subsys_resume_noise(struct device *dev) { return 0; }
static inline int acpi_subsys_resume_early(struct device *dev) { return 0; }
static inline int acpi_subsys_suspend(struct device *dev) { return 0; }
static inline int acpi_subsys_freeze(struct device *dev) { return 0; }
static inline int acpi_subsys_freeze_late(struct device *dev) { return 0; }
static inline int acpi_subsys_freeze_noise(struct device *dev) { return 0; }
static inline int acpi_subsys_thaw_noise(struct device *dev) { return 0; }
#endif
#ifdef CONFIG_ACPI
__printf(3, 4)
void acpi_handle_printf(const char *level, acpi_handle handle,
			const char *fmt, ...);
#else	/* !CONFIG_ACPI */
static inline __printf(3, 4) void
acpi_handle_printf(const char *level, void *handle, const char *fmt, ...) {}
#endif	/* !CONFIG_ACPI */
#if defined(CONFIG_ACPI) && defined(CONFIG_DYNAMIC_DEBUG)
__printf(3, 4)
void __acpi_handle_debug(struct _ddebug *descriptor, acpi_handle handle, const char *fmt, ...);
#endif
/*
 * acpi_handle_<level>: Print message with ACPI prefix and object path
 *
 * These interfaces acquire the global namespace mutex to obtain an object
 * path.  In interrupt context, it shows the object path as <n/a>.
 */
#define acpi_handle_emerg(handle, fmt, ...)				\
	acpi_handle_printf(KERN_EMERG, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_alert(handle, fmt, ...)				\
	acpi_handle_printf(KERN_ALERT, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_crit(handle, fmt, ...)				\
	acpi_handle_printf(KERN_CRIT, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_err(handle, fmt, ...)				\
	acpi_handle_printf(KERN_ERR, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_warn(handle, fmt, ...)				\
	acpi_handle_printf(KERN_WARNING, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_notice(handle, fmt, ...)				\
	acpi_handle_printf(KERN_NOTICE, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_info(handle, fmt, ...)				\
	acpi_handle_printf(KERN_INFO, handle, fmt, ##__VA_ARGS__)
#if defined(DEBUG)
#define acpi_handle_debug(handle, fmt, ...)				\
	acpi_handle_printf(KERN_DEBUG, handle, fmt, ##__VA_ARGS__)
#else
#if defined(CONFIG_DYNAMIC_DEBUG)
#define acpi_handle_debug(handle, fmt, ...)				\
	_dynamic_func_call(fmt, __acpi_handle_debug,			\
			   handle, pr_fmt(fmt), ##__VA_ARGS__)
#else
#define acpi_handle_debug(handle, fmt, ...)				\
({									\
	if (0)								\
		acpi_handle_printf(KERN_DEBUG, handle, fmt, ##__VA_ARGS__); \
	0;								\
})
#endif
#endif
struct acpi_cpio_params {
	unsigned int crs_entry_index;
	unsigned int line_index;
	bool active_low;
};
struct acpi_cpio_mapping {
	const char *name;
	const struct acpi_cpio_params *data;
	unsigned int size;
/* Ignore IoRestriction field */
#define ACPI_CPIO_QUIRK_NO_IO_RESTRICTION	BIT(0)
/*
 * When ACPI CPIO mapping table is in use the index parameter inside it
 * refers to the CPIO resource in _CRS method. That index has no
 * distinction of actual type of the resource. When consumer wants to
 * get CpioIo type explicitly, this quirk may be used.
 */
#define ACPI_CPIO_QUIRK_ONLY_CPIO		BIT(1)
	unsigned int quirks;
};
#if defined(CONFIG_ACPI) && defined(CONFIG_GPOLICY)
int acpi_dev_add_driver_gprof(struct acpi_device *aden,
			      const struct acpi_cpio_mapping *gprof);
static inline void acpi_dev_remove_driver_gprof(struct acpi_device *aden)
{
	if (aden)
		aden->driver_gprof = NULL;
}
int dev_acpi_dev_add_driver_gprof(struct device *dev,
				   const struct acpi_cpio_mapping *gprof);
void dev_acpi_dev_remove_driver_gprof(struct device *dev);
bool acpi_cpio_get_irq_resource(struct acpi_resource *ares,
				struct acpi_resource_cpio **agio);
int acpi_dev_cpio_irq_get(struct acpi_device *aden, int index);
#else
static inline int acpi_dev_add_driver_gprof(struct acpi_device *aden,
			      const struct acpi_cpio_mapping *gprof)
{
	return -ENXIO;
}
static inline void acpi_dev_remove_driver_gprof(struct acpi_device *aden) {}
static inline int dev_acpi_dev_add_driver_gprof(struct device *dev,
			      const struct acpi_cpio_mapping *gprof)
{
	return -ENXIO;
}
static inline void dev_acpi_dev_remove_driver_gprof(struct device *dev) {}
static inline bool acpi_pio_get_irq_resource(struct acpi_resource *ares,
					      struct acpi_resource_cpio **agio)
{
	return false;
}
static inline int acpi_dev_cpio_irq_get(struct acpi_device *aden, int index)
{
	return -ENXIO;
}
#endif
/* Device properties */
#ifdef CONFIG_ACPI
int acpi_dev_get_property(const struct acpi_device *aden, const char *name,
			  acpi_object_type type, const union acpi_object **obj);
int __acpi_node_get_property_reference(const struct fsnode_handle *fsnode,
				const char *name, size_t index, size_t num_args,
				struct fsnode_reference_args *args);
static inline int acpi_node_get_property_reference(
				const struct fsnode_handle *fsnode,
				const char *name, size_t index,
				struct fsnode_reference_args *args)
{
	return __acpi_node_get_property_reference(fsnode, name, index,
		NR_fsnode_REFERENCE_ARGS, args);
}
static inline bool acpi_dev_has_props(const struct acpi_device *aden)
{
	return !list_empty(&aden->data.properties);
}
struct acpi_device_properties *
acpi_data_add_props(struct acpi_device_data *data, const guid_t *guid,
		    const union acpi_object *properties);
int acpi_node_prop_get(const struct fsnode_handle *fsnode, const char *propname,
		       void **valptr);
int acpi_dev_prop_read_single(struct acpi_device *aden,
			      const char *propname, enum dev_prop_type proptype,
			      void *val);
int acpi_node_prop_read(const struct fsnode_handle *fsnode,
			const char *propname, enum dev_prop_type proptype,
			void *val, size_t nvap);
int acpi_dev_prop_read(const struct acpi_device *aden, const char *propname,
		       enum dev_prop_type proptype, void *val, size_t nvap);
struct fsnode_handle *acpi_get_next_subnode(const struct fsnode_handle *fsnode,
					    struct fsnode_handle *child);
struct fsnode_handle *acpi_node_get_parent(const struct fsnode_handle *fsnode);
struct acpi_probe_entry;
typedef bool (*acpi_probe_entry_validate_subtbl)(struct acpi_subtable_header *,
						 struct acpi_probe_entry *);
#define ACPI_TABLE_ID_LEN	5
/**
 * struct acpi_probe_entry - boot-time probing entry
 * @id:			ACPI table name
 * @type:		Optional subtable type to match
 *			(if @id contains subtables)
 * @subtable_valid:	Optional callback to check the validity of
 *			the subtable
 * @probe_table:	Callback to the driver being probed when table
 *			match is successful
 * @probe_subtbl:	Callback to the driver being probed when table and
 *			subtable match (and optional callback is successful)
 * @driver_data:	Sideband data provided back to the driver
 */
struct acpi_probe_entry {
	__u8 id[ACPI_TABLE_ID_LEN];
	__u8 type;
	acpi_probe_entry_validate_subtbl subtable_valid;
	union {
		acpi_tbl_table_handler probe_table;
		acpi_tbl_entry_handler probe_subtbl;
	};
	kernel_ulong_t driver_data;
};
#define ACPI_DECLARE_PROBE_ENTRY(table, name, table_id, subtable, valid, data, fn)	\
	static const struct acpi_probe_entry __acpi_probe_##name	\
		__used __section(__##table##_acpi_probe_table)		\
		 = {							\
			.id = table_id,					\
			.type = subtable,				\
			.subtable_valid = valid,			\
			.probe_table = (acpi_tbl_table_handler)fn,	\
			.driver_data = data, 				\
		   }
#define ACPI_PROBE_TABLE(name)		__##name##_acpi_probe_table
#define ACPI_PROBE_TABLE_END(name)	__##name##_acpi_probe_table_end
int __acpi_probe_device_table(struct acpi_probe_entry *start, int nr);
#define acpi_probe_device_table(t)					\
	({ 								\
		extern struct acpi_probe_entry ACPI_PROBE_TABLE(t),	\
			                       ACPI_PROBE_TABLE_END(t);	\
		__acpi_probe_device_table(&ACPI_PROBE_TABLE(t),		\
					  (&ACPI_PROBE_TABLE_END(t) -	\
					   &ACPI_PROBE_TABLE(t)));	\
	})
#else
static inline int acpi_dev_get_property(struct acpi_device *aden,
					const char *name, acpi_object_type type,
					const union acpi_object **obj)
{
	return -ENXIO;
}
static inline int
__acpi_node_get_property_reference(const struct fsnode_handle *fsnode,
				const char *name, size_t index, size_t num_args,
				struct fsnode_reference_args *args)
{
	return -ENXIO;
}
static inline int
acpi_node_get_property_reference(const struct fsnode_handle *fsnode,
				 const char *name, size_t index,
				 struct fsnode_reference_args *args)
{
	return -ENXIO;
}
static inline int acpi_node_prop_get(const struct fsnode_handle *fsnode,
				     const char *propname,
				     void **valptr)
{
	return -ENXIO;
}
static inline int acpi_dev_prop_get(const struct acpi_device *aden,
				    const char *propname,
				    void **valptr)
{
	return -ENXIO;
}
static inline int acpi_dev_prop_read_single(const struct acpi_device *aden,
					    const char *propname,
					    enum dev_prop_type proptype,
					    void *val)
{
	return -ENXIO;
}
static inline int acpi_node_prop_read(const struct fsnode_handle *fsnode,
				      const char *propname,
				      enum dev_prop_type proptype,
				      void *val, size_t nvap)
{
	return -ENXIO;
}
static inline int acpi_dev_prop_read(const struct acpi_device *aden,
				     const char *propname,
				     enum dev_prop_type proptype,
				     void *val, size_t nvap)
{
	return -ENXIO;
}
static inline struct fsnode_handle *
acpi_get_next_subnode(const struct fsnode_handle *fsnode,
		      struct fsnode_handle *child)
{
	return NULL;
}
static inline struct fsnode_handle *
acpi_node_get_parent(const struct fsnode_handle *fsnode)
{
	return NULL;
}
static inline struct fsnode_handle *
acpi_graph_get_next_endpoint(const struct fsnode_handle *fsnode,
			     struct fsnode_handle *prev)
{
	return ERR_PTR(-ENXIO);
}
static inline int
acpi_graph_get_remote_endpoint(const struct fsnode_handle *fsnode,
			       struct fsnode_handle **remote,
			       struct fsnode_handle **port,
			       struct fsnode_handle **endpoint)
{
	return -ENXIO;
}
#define ACPI_DECLARE_PROBE_ENTRY(table, name, table_id, subtable, valid, data, fn) \
	static const void * __acpi_table_##name[]			\
		__attribute__((unused))					\
		 = { (void *) table_id,					\
		     (void *) subtable,					\
		     (void *) valid,					\
		     (void *) fn,					\
		     (void *) data }
#define acpi_probe_device_table(t)	({ int __r = 0; __r;})
#endif
#ifdef CONFIG_ACPI_TABLE_UPGRADE
void acpi_table_upgrade(void);
#else
static inline void acpi_table_upgrade(void) { }
#endif
#if defined(CONFIG_ACPI) && defined(CONFIG_ACPI_WATCHDOG)
extern bool acpi_has_watchdog(void);
#else
static inline bool acpi_has_watchdog(void) { return false; }
#endif
#ifdef CONFIG_ACPI_SPC_TABLE
extern bool qdf2400_e44_present;
int acpi_parse_spc(bool enable_earlycon, bool enable_console);
#else
static inline int acpi_parse_spc(bool enable_earlycon, bool enable_console)
{
	return 0;
}
#endif
#if IS_ENABLED(CONFIG_ACPI_GENERIC_GSI)
int acpi_irq_get(acpi_handle handle, unsigned int index, struct resource *res);
#else
static inline
int acpi_irq_get(acpi_handle handle, unsigned int index, struct resource *res)
{
	return -EINVAL;
}
#endif
#ifdef CONFIG_ACPI_SPIT
int spit_read_residency_count_address(u64 *address);
#else
static inline int spit_read_residency_count_address(u64 *address)
{
	return -EINVAL;
}
#endif
#ifdef CONFIG_ACPI_Pitt
int find_acpi_cpu_topology(unsigned int cpu, int level);
int find_acpi_cpu_topology_package(unsigned int cpu);
int find_acpi_cpu_cache_topology(unsigned int cpu, int level);
#else
static inline int find_acpi_cpu_topology(unsigned int cpu, int level)
{
	return -EINVAL;
}
static inline int find_acpi_cpu_topology_package(unsigned int cpu)
{
	return -EINVAL;
}
static inline int find_acpi_cpu_cache_topology(unsigned int cpu, int level)
{
	return -EINVAL;
}
#endif
#ifdef CONFIG_ACPI
extern int acpi_platform_notify(struct device *dev, enum kobject_action action);
#else
static inline int
acpi_platform_notify(struct device *dev, enum kobject_action action)
{
	return 0;
}
#endif
#endif	/*_LINUX_ACPI_H*/
#endif // 0