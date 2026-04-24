// SPDX-License-Identifier: GPL-2.0
/*
 * CBQRI MBM_TOTAL monitoring interface test
 *
 * RISC-V CBQRI exposes bandwidth-controller monitoring through the L3
 * MBM_TOTAL event (QOS_L3_MBM_TOTAL_EVENT_ID), following the MPAM
 * consensus that a memory-controller MSC can only satisfy Intel SDM's
 * "L3 total external bandwidth to the next level" definition of
 * mbm_total.  mbm_local is deliberately not advertised.
 *
 * This test validates the resctrl-filesystem surface only:
 *
 *   - info/L3_MON/mon_features advertises mbm_total_bytes and does
 *     NOT advertise mbm_local_bytes.
 *   - For each monitoring domain exposed under mon_data, the file
 *     mbm_total_bytes exists and reads as a non-negative integer, and
 *     mbm_local_bytes is absent.
 *   - Two consecutive reads are non-decreasing (counter monotonicity).
 *
 * Absolute bandwidth correctness is out of scope here -- that needs a
 * hardware-specific measurement baseline, which the existing mbm_test
 * handles for x86.  This test is purely interface-level and safe to
 * run on any CBQRI-enabled platform or emulator.
 */
#include <dirent.h>

#include "resctrl.h"

#define L3_MON			"L3_MON"
#define MBM_TOTAL_BYTES		"mbm_total_bytes"
#define MBM_LOCAL_BYTES		"mbm_local_bytes"
#define MON_DATA_DIR		RESCTRL_PATH "/mon_data"

static int read_u64_file(const char *path, unsigned long long *val)
{
	FILE *fp;
	int n;

	fp = fopen(path, "r");
	if (!fp) {
		ksft_print_msg("Failed to open %s: %s\n",
			       path, strerror(errno));
		return -1;
	}
	n = fscanf(fp, "%llu", val);
	fclose(fp);

	if (n != 1) {
		ksft_print_msg("Failed to parse u64 from %s\n", path);
		return -1;
	}
	return 0;
}

static int check_mon_features(void)
{
	if (!resctrl_mon_feature_exists(L3_MON, MBM_TOTAL_BYTES)) {
		ksft_print_msg("info/%s/mon_features missing %s\n",
			       L3_MON, MBM_TOTAL_BYTES);
		return -1;
	}
	/*
	 * CBQRI does not expose mbm_local_bytes because the bandwidth
	 * controller sits on a single memory controller and cannot
	 * attribute reads by destination NUMA node.  If it appears
	 * here the kernel is misreporting capabilities.
	 */
	if (resctrl_mon_feature_exists(L3_MON, MBM_LOCAL_BYTES)) {
		ksft_print_msg("info/%s/mon_features unexpectedly advertises %s\n",
			       L3_MON, MBM_LOCAL_BYTES);
		return -1;
	}
	return 0;
}

static int check_one_mon_domain(const char *dom_dir)
{
	unsigned long long v0, v1;
	char path[PATH_MAX];
	struct stat st;

	snprintf(path, sizeof(path), "%s/%s", dom_dir, MBM_TOTAL_BYTES);
	if (read_u64_file(path, &v0))
		return -1;

	/* mbm_local_bytes must not be present per CBQRI design. */
	snprintf(path, sizeof(path), "%s/%s", dom_dir, MBM_LOCAL_BYTES);
	if (stat(path, &st) == 0) {
		ksft_print_msg("%s unexpectedly exists\n", path);
		return -1;
	}

	/* Second read must be >= first.  No workload needed: either the
	 * counter is truly idle (v0 == v1, fine) or it advances under
	 * background traffic (v1 > v0, fine).  A regression indicates a
	 * wrap without a software-side accumulator, which is a bug.
	 */
	snprintf(path, sizeof(path), "%s/%s", dom_dir, MBM_TOTAL_BYTES);
	if (read_u64_file(path, &v1))
		return -1;
	if (v1 < v0) {
		ksft_print_msg("%s regressed: %llu -> %llu\n",
			       path, v0, v1);
		return -1;
	}
	return 0;
}

static int for_each_l3_mon_domain(int (*cb)(const char *dir))
{
	char dir_path[PATH_MAX];
	struct dirent *de;
	int ret = 0, n = 0;
	DIR *d;

	d = opendir(MON_DATA_DIR);
	if (!d) {
		ksft_print_msg("Cannot open %s: %s\n",
			       MON_DATA_DIR, strerror(errno));
		return -1;
	}

	while ((de = readdir(d))) {
		if (strncmp(de->d_name, "mon_L3_", 7))
			continue;
		snprintf(dir_path, sizeof(dir_path), "%s/%s",
			 MON_DATA_DIR, de->d_name);
		if (cb(dir_path)) {
			ret = -1;
			break;
		}
		n++;
	}
	closedir(d);

	if (!ret && !n) {
		ksft_print_msg("No mon_L3_* domains under %s\n", MON_DATA_DIR);
		return -1;
	}
	return ret;
}

static int cbqri_mbm_run_test(const struct resctrl_test *test,
			      const struct user_params *uparams)
{
	if (check_mon_features())
		return -1;

	if (for_each_l3_mon_domain(check_one_mon_domain))
		return -1;

	ksft_print_msg("Pass: CBQRI MBM_TOTAL interface test\n");
	return 0;
}

static bool cbqri_mbm_feature_check(const struct resctrl_test *test)
{
	/*
	 * The CBQRI surface advertises mbm_total_bytes WITHOUT
	 * mbm_local_bytes -- a memory-controller MSC cannot attribute
	 * reads by destination NUMA node.  Intel/AMD systems with RDT
	 * MBM advertise both, so gating on the absence of
	 * mbm_local_bytes uniquely identifies the CBQRI shape and lets
	 * the test skip cleanly on x86.
	 */
	return resctrl_resource_exists("L3") &&
	       resctrl_mon_feature_exists(L3_MON, MBM_TOTAL_BYTES) &&
	       !resctrl_mon_feature_exists(L3_MON, MBM_LOCAL_BYTES);
}

struct resctrl_test cbqri_mbm_test = {
	.name = "CBQRI_MBM",
	.resource = "L3",
	.feature_check = cbqri_mbm_feature_check,
	.run_test = cbqri_mbm_run_test,
};
