#include <linux/syscalls.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/prctl.h>

#define	GBP_ADD		_IOW('G', 32, struct gbp_information)
#define	GBP_REMOVE	_IOW('G', 33, struct gbp_information)

#define MAX_ENTRY_SLOTS	32

struct gbp_session {
	struct mutex mutex;
	struct list_head list;
	unsigned long bp_ids;

	unsigned long bp_slots;
	struct task_struct *blocked_task[MAX_ENTRY_SLOTS];
	spinlock_t entry_lock;
	wait_queue_head_t waitq;
};

struct gbp_information {
	int fd;
	int ___pad0;
	u64 offset;
	char __pad1[16];
};

struct gbp_bp {
	struct uprobe_consumer uc;
	struct gbp_session *gbp_s;
	unsigned int bp_id;

	struct inode *inode;
	unsigned long offset;
	struct list_head node;
};

static int gbp_handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
	struct gbp_session *gbp_s;
	struct gbp_bp *bp;
	unsigned long slot;

	bp = container_of(self, struct gbp_bp, uc);
	gbp_s = bp->gbp_s;

	spin_lock(&gbp_s->entry_lock);
	if (gbp_s->bp_slots == ULONG_MAX) {
		pr_err("No free slots\n");
		goto out;
	}
	slot = ffz(gbp_s->bp_slots);
	if (slot >= MAX_ENTRY_SLOTS) {
		pr_err("No free slots #2\n");
		goto out;
	}

	gbp_s->bp_slots |=  1UL << slot;

	get_task_struct(current);
	gbp_s->blocked_task[slot] = current;
	__set_current_state(TASK_KILLABLE);
	set_tsk_need_resched(current);

	wake_up_all(&gbp_s->waitq);

out:
	spin_unlock(&gbp_s->entry_lock);
	return 0;
}

static int gbp_ret_handler(struct uprobe_consumer *self,
		unsigned long func,
		struct pt_regs *regs)
{
	return 0;
}

static bool gbp_filter(struct uprobe_consumer *self,
		enum uprobe_filter_ctx ctx, struct mm_struct *mm)
{
	struct task_struct *task = current;

	if (ctx == UPROBE_FILTER_MMAP)
		return task -> global_bp_flags & PR_GLOBAL_BREAKPOINT_EN ?
			true : false;
	pr_err("%s(%d) %d\n", __func__, __LINE__, ctx);
	return false;
}

static int global_bp_release(struct inode *inode, struct file *file)
{
	struct gbp_session *gbp_s = file->private_data;
	struct gbp_bp *bp, *tmp;

	/* no gbp_s->mutex because we are the last one left */
	list_for_each_entry_safe(bp, tmp, &gbp_s->list, node) {
		uprobe_unregister(bp->inode, bp->offset, &bp->uc);
		iput(bp->inode);
		list_del(&bp->node);
		kfree(bp);
	}

	/* the uprobe is gone, none should show up, no gbp_s->entry_lock */
	while (gbp_s->bp_slots) {
		struct task_struct *task;
		unsigned int slot;

		slot = __ffs(gbp_s->bp_slots);
		gbp_s->bp_slots &= ~(1UL << slot);
		task = gbp_s->blocked_task[slot];
		wake_up_process(task);
		put_task_struct(task);
	}
	kfree(gbp_s);
	return 0;
}

static ssize_t global_bp_read(struct file *file, char __user *buf, size_t count,
		loff_t *ppos)
{
	struct gbp_session *gbp_s = file->private_data;
	pid_t entry;
	unsigned long flags;
	unsigned int have = 0;
	unsigned int slot;
	unsigned int can_wait = !(file->f_flags & O_NONBLOCK);
	int ret;

	if (count != sizeof(entry))
		return -EINVAL;

	do {
		if (!gbp_s->bp_slots && !can_wait)
			return -EAGAIN;

		ret = wait_event_interruptible(gbp_s->waitq, gbp_s->bp_slots);
		if (ret)
			return ret;

		spin_lock_irqsave(&gbp_s->entry_lock, flags);
		if (gbp_s->bp_slots) {
			slot = __ffs(gbp_s->bp_slots);
			entry = gbp_s->blocked_task[slot]->pid;
			have = 1;
		}
		spin_unlock_irqrestore(&gbp_s->entry_lock, flags);
	} while (!have);

	if (copy_to_user(buf, &entry, sizeof(entry)))
		return -EFAULT;

	return count;
}

static ssize_t global_bp_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	struct gbp_session *gbp_s = file->private_data;
	pid_t w_pid;
	struct task_struct *task;
	unsigned long flags;
	int have = 0;
	int ret;

	if (count != sizeof(w_pid))
		return -EINVAL;

	if (copy_from_user(&w_pid, buf, sizeof(w_pid)))
		return -EFAULT;

	spin_lock_irqsave(&gbp_s->entry_lock, flags);
	if (gbp_s->bp_slots) {
		unsigned long mask;
		unsigned int slot;

		mask = gbp_s->bp_slots;
		do {

			slot = __ffs(mask);
			mask &= ~(1UL << slot);
			task = gbp_s->blocked_task[slot];
			if (task->pid == w_pid) {
				have = 1;
				gbp_s->bp_slots &= ~(1UL << slot);
				break;
			}
		} while (mask);
	}
	spin_unlock_irqrestore(&gbp_s->entry_lock, flags);

	if (!have)
		return -ESRCH;

	ret = wake_up_process(task);
	if (ret == 1)
		ret = count;

	put_task_struct(task);
	return ret;
}

static unsigned int global_bp_poll(struct file *file, poll_table *wait)
{
	struct gbp_session *gbp_s = file->private_data;
	unsigned long flags;
	unsigned int ret = 0;

	poll_wait(file, &gbp_s->waitq, wait);

	spin_lock_irqsave(&gbp_s->entry_lock, flags);
	if (gbp_s->bp_slots)
		ret = POLLIN | POLLRDNORM;
	spin_unlock_irqrestore(&gbp_s->entry_lock, flags);

	return ret;
}

static int global_bp_add(struct gbp_session *gbp,
		struct gbp_information __user *user_arg)
{
	struct gbp_bp *bp;
	struct fd f;
	struct inode *inode;
	struct gbp_information gbp_info;
	int ret;
	unsigned int bp_id;

	ret = copy_from_user(&gbp_info, user_arg, sizeof(gbp_info));
	if (ret)
		return -EFAULT;

	f = fdget(gbp_info.fd);
	if (!f.file)
		return -EBADF;

	if ((f.file->f_flags & O_ACCMODE) != O_RDWR) {
		ret = -EPERM;
		goto err_put_f;
	}

	ret = -EBADF;
	inode = file_inode(f.file);
	if (!inode)
		goto err_put_f;

	inode = igrab(inode);
	if (!inode)
		goto err_put_f;

	bp = kzalloc(GFP_KERNEL, sizeof(*bp));
	if (!bp) {
		ret = -ENOMEM;
		goto err_put_i;
	}

	mutex_lock(&gbp->mutex);
	if (gbp->bp_ids == ULONG_MAX) {
		ret = -ENOSPC;
		goto err_free;

	}
	bp_id = ffz(gbp->bp_ids);
	gbp->bp_ids |= 1UL << bp_id;

	bp->bp_id = bp_id;
	bp->inode = inode;
	bp->offset = gbp_info.offset;

	bp->uc.handler = gbp_handler;
	if (0)
		bp->uc.ret_handler = gbp_ret_handler;
	bp->uc.filter = gbp_filter;

	ret = uprobe_register(inode, bp->offset, &bp->uc);
	if (ret) {
		pr_err("%s(%d) %d\n", __func__, __LINE__, ret);
		goto err_uprobe;
	}
	list_add(&bp->node, &gbp->list);
	bp->gbp_s = gbp;
	mutex_unlock(&gbp->mutex);
	fdput(f);
	return bp_id;
err_uprobe:
	gbp->bp_ids &= ~( 1UL << bp_id);
err_free:
	mutex_unlock(&gbp->mutex);
	kfree(bp);
err_put_i:
	iput(inode);
err_put_f:
	fdput(f);
	return ret;
}

static int global_bp_remove(struct gbp_session *gbp_s, unsigned int bp_id)
{
	struct gbp_bp *bp, *tmp;

	mutex_lock(&gbp_s->mutex);

	list_for_each_entry_safe(bp, tmp, &gbp_s->list, node) {
		if (bp->bp_id == bp_id) {
			uprobe_unregister(bp->inode, bp->offset, &bp->uc);
			iput(bp->inode);
			list_del(&bp->node);
			kfree(bp);
			mutex_unlock(&gbp_s->mutex);
			return 0;
		}
	}
	mutex_unlock(&gbp_s->mutex);
	return -EINVAL;
}

static long global_bp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct gbp_session *gbp_s = file->private_data;
	int ret;

	switch (cmd) {
	case GBP_ADD:
		ret = global_bp_add(gbp_s,
				(struct gbp_information __user *) arg);
		break;

	case GBP_REMOVE:
		ret = global_bp_remove(gbp_s, arg);
		break;

	default:
		ret = -EINVAL;
	};
	return ret;
}

static const struct file_operations global_bp_fops = {
	.llseek                 = no_llseek,
	.release                = global_bp_release,
	.read                   = global_bp_read,
	.write			= global_bp_write,
	.poll                   = global_bp_poll,
	.unlocked_ioctl         = global_bp_ioctl,
	.compat_ioctl           = global_bp_ioctl,
};

SYSCALL_DEFINE1(gbp_session_create, unsigned int, flags)
{
	int fd;
	int f_flags = O_RDWR | O_CLOEXEC;
	struct gbp_session *gbp_s;
	int size;

	if (flags)
		return -EINVAL;

	size = sizeof(struct gbp_session);
	gbp_s = kzalloc(size, GFP_KERNEL);
	if (!gbp_s)
		return -ENOMEM;

	INIT_LIST_HEAD(&gbp_s->list);
	mutex_init(&gbp_s->mutex);
	spin_lock_init(&gbp_s->entry_lock);
	init_waitqueue_head(&gbp_s->waitq);

	fd = anon_inode_getfd("[gbp session]", &global_bp_fops, gbp_s, f_flags);
	if (fd < 0)
		goto err;
	return fd;
err:
	kfree(gbp_s);
	return fd;
}
