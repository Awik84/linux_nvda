/* SPDX-License-Identifier: ISC */

#include "mt7603.h"

static int
mt7603_reset_read(struct seq_file *s, void *data)
{
	struct mt7603_dev *dev = dev_get_drvdata(s->private);
	static const char * const reset_cause_str[] = {
		[RESET_CAUSE_TX_HANG] = "TX hang",
		[RESET_CAUSE_TX_BUSY] = "TX DMA busy stuck",
		[RESET_CAUSE_RX_BUSY] = "RX DMA busy stuck",
		[RESET_CAUSE_RX_PSE_BUSY] = "RX PSE busy stuck",
		[RESET_CAUSE_BEACON_STUCK] = "Beacon stuck",
		[RESET_CAUSE_MCU_HANG] = "MCU hang",
		[RESET_CAUSE_RESET_FAILED] = "PSE reset failed",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(reset_cause_str); i++) {
		if (!reset_cause_str[i])
			continue;

		seq_printf(s, "%20s: %u\n", reset_cause_str[i],
			   dev->reset_cause[i]);
	}

	return 0;
}

static int
mt7603_radio_read(struct seq_file *s, void *data)
{
	struct mt7603_dev *dev = dev_get_drvdata(s->private);

	seq_printf(s, "Sensitivity: %d\n", dev->sensitivity);
	seq_printf(s, "False CCA: ofdm=%d cck=%d\n",
		   dev->false_cca_ofdm, dev->false_cca_cck);

	return 0;
}

static int
mt7603_edcca_set(void *data, u64 val)
{
	struct mt7603_dev *dev = data;

	mutex_lock(&dev->mt76.mutex);

	dev->ed_monitor_enabled = !!val;
	dev->ed_monitor = dev->ed_monitor_enabled &&
			  dev->mt76.region == NL80211_DFS_ETSI;
	mt7603_init_edcca(dev);

	mutex_unlock(&dev->mt76.mutex);

	return 0;
}

static int
mt7603_edcca_get(void *data, u64 *val)
{
	struct mt7603_dev *dev = data;

	*val = dev->ed_monitor_enabled;
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_edcca, mt7603_edcca_get,
			 mt7603_edcca_set, "%lld\n");

void mt7603_init_debugfs(struct mt7603_dev *dev)
{
	struct dentry *dir;

	dir = mt76_register_debugfs(&dev->mt76);
	if (!dir)
		return;

	debugfs_create_file("edcca", 0600, dir, dev, &fops_edcca);
	debugfs_create_u32("reset_test", 0600, dir, &dev->reset_test);
	debugfs_create_devm_seqfile(dev->mt76.dev, "reset", dir,
				    mt7603_reset_read);
	debugfs_create_devm_seqfile(dev->mt76.dev, "radio", dir,
				    mt7603_radio_read);
}
