#include <taihen.h>
#include <string.h>
#include <sys/syslimits.h>
#include <stdio.h>
#include <vitasdkkern.h>
#include <psp2/types.h>

uint32_t *ScePower_41C8 = NULL;
uint32_t *ScePower_41CC = NULL;

static SceUID g_mutex_cpufreq_uid = -1;
static tai_hook_ref_t g_hookrefs[4];
static SceUID g_injects[1];
static SceUID g_hooks[4];
int (*ScePervasiveForDriver_0xE9D95643)(int mul, int ndiv);


int (*_kscePowerSetArmClockFrequency)(int freq);
int (*_kscePowerSetBusClockFrequency)(int freq);
int (*_kscePowerSetGpuEs4ClockFrequency)(int a1, int a2);
int (*_kscePowerSetGpuXbarClockFrequency)(int freq);

int module_get_export_func (SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);
int module_get_offset (SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);
void oc_max_holy_shit();

int kscePowerSetArmClockFrequency_patched(int freq) {
    int ret = ksceKernelLockMutex(g_mutex_cpufreq_uid, 1, NULL);
    if (ret < 0)
        return ret;

    freq = 500;

    if (freq > 444 && freq <= 500) {
        TAI_CONTINUE(int, g_hookrefs[0], 444);
        oc_max_holy_shit();
        ret = 0;
    } else {
        ret = TAI_CONTINUE(int, g_hookrefs[0], freq);
    }

    ksceKernelUnlockMutex(g_mutex_cpufreq_uid, 1);
    return ret;
}

int kscePowerSetBusClockFrequency_patched(int freq) {
    return TAI_CONTINUE(int, g_hookrefs[1], 222);
}

int kscePowerSetGpuEs4ClockFrequency_patched(int a1, int a2) {
    a1 = 222;
    a2 = 222;
    return TAI_CONTINUE(int, g_hookrefs[2], a1, a2);
}

int kscePowerSetGpuXbarClockFrequency_patched(int freq) {
    return TAI_CONTINUE(int, g_hookrefs[3], 166);
}

void oc_max_holy_shit()
{
	// Apply mul:div (15:0)
    ScePervasiveForDriver_0xE9D95643(15, 16 - 0);

    // Store global freq & mul for kscePowerGetArmClockFrequency()
    *ScePower_41C8 = 500;
    *ScePower_41CC = 15;
}


void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {


	tai_module_info_t tai_info;
    tai_info.size = sizeof(tai_module_info_t);
    taiGetModuleInfoForKernel(KERNEL_PID, "ScePower", &tai_info);

    module_get_offset(KERNEL_PID, tai_info.modid, 1, 0x41C8, (uintptr_t *)&ScePower_41C8);
    module_get_offset(KERNEL_PID, tai_info.modid, 1, 0x41CC, (uintptr_t *)&ScePower_41CC);


	module_get_export_func(KERNEL_PID,
        "SceLowio", 0xE692C727, 0xE9D95643, (uintptr_t *)&ScePervasiveForDriver_0xE9D95643);

    module_get_export_func(KERNEL_PID,
            "ScePower", 0x1590166F, 0x74DB5AE5, (uintptr_t *)&_kscePowerSetArmClockFrequency);
    module_get_export_func(KERNEL_PID,
            "ScePower", 0x1590166F, 0xB8D7B3FB, (uintptr_t *)&_kscePowerSetBusClockFrequency);
    module_get_export_func(KERNEL_PID,
	        "ScePower", 0x1590166F, 0x264C24FC, (uintptr_t *)&_kscePowerSetGpuEs4ClockFrequency);
    module_get_export_func(KERNEL_PID,
            "ScePower", 0x1590166F, 0xA7739DBE, (uintptr_t *)&_kscePowerSetGpuXbarClockFrequency);

    g_mutex_cpufreq_uid = ksceKernelCreateMutex("psvs_mutex_cpufreq", 0, 0, NULL);


    const uint8_t nop[] = {0x00, 0xBF};
    g_injects[0] = taiInjectAbsForKernel(KERNEL_PID, (void *)((uintptr_t)ScePervasiveForDriver_0xE9D95643 + 0x1D), &nop, 2);
	
	g_hooks[0] = taiHookFunctionExportForKernel(KERNEL_PID, &g_hookrefs[0],
            "ScePower", 0x1590166F, 0x74DB5AE5, kscePowerSetArmClockFrequency_patched);
    g_hooks[1] = taiHookFunctionExportForKernel(KERNEL_PID, &g_hookrefs[1],
            "ScePower", 0x1590166F, 0xB8D7B3FB, kscePowerSetBusClockFrequency_patched);
    g_hooks[2] = taiHookFunctionExportForKernel(KERNEL_PID, &g_hookrefs[2],
            "ScePower", 0x1590166F, 0x264C24FC, kscePowerSetGpuEs4ClockFrequency_patched);
    g_hooks[3] = taiHookFunctionExportForKernel(KERNEL_PID, &g_hookrefs[3],
            "ScePower", 0x1590166F, 0xA7739DBE, kscePowerSetGpuXbarClockFrequency_patched);

	oc_max_holy_shit();	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) 
{
    for (int i = 0; i < 4; i++)
	{
        if (g_hooks[i] >= 0)
            taiHookReleaseForKernel(g_hooks[i], g_hookrefs[i]);
	}

	if (g_injects[0] >= 0)
        taiInjectReleaseForKernel(g_injects[0]);
	
	if (g_mutex_cpufreq_uid >= 0)
        ksceKernelDeleteMutex(g_mutex_cpufreq_uid);

	return SCE_KERNEL_STOP_SUCCESS;
}