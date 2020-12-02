# Morris二叉树遍历

该算法可以实现对二叉树的无栈非递归的前、中、后序遍历。Morris算法使用线索二叉树的方法解决遍历到子节点的时候怎样返回到父节点。在Morris算法中只需要利用叶子节点的左右空指针指向某种顺序遍历下的前驱节点或后继节点即可。
在本项目中，红黑树`quic_rbt_t`即是一种二叉树数据结构，它应用在重传模块中，用于发送时记录发送的数据包，并在确认收到或判定丢失的数据包时，对这个数据包展开一系列后续操作。因此需要一个对二叉树遍历的方法。

## 红黑树数据结构拓展
通常，一个红黑树节点应包含四个字段，为方便Morris算法建立线索，并且不破坏红黑树的结构情况下，扩充一个字段，则基础二叉树节点的结构如下：
```
quic_rbt_t {
    quic_rbt_t *rb_p;
    quic_rbt_t *rb_r;
    quic_rbt_t *rb_l;
    quic_rbt_t *morris_link;
    uint8_t rb_color
}
```

在遍历时，需要提供一个辅助的迭代器，定义如下：
```
quic_rbt_iterator_t {
    bool interrupt_1;
    bool interrupt_2;

    quic_rbt_t *cur;
    quic_rbt_t *mr;
}
```

## 二叉树遍历

在本项目中，使用Morris遍历算法主要是应用在红黑树上，红黑树是一种有序的二叉树，因此使用中序遍历较为合适。
伪代码如下：

```
quic_rbt_iterator_next(iter) {

    if (iter.interrupt_1) {
        goto travel_interrupt_1;
    }
    if (iter.interrupt_2) {
        goto travel_interrupt_2;
    }

    while (is_not_nil(iter.cur)) {
        if (is_nil(iter.cur.left)) {
            // 无左子树的情况下，先遍历当前节点
            iter.interrupt_1 = true;
            return;

            // 遍历右子树
travel_interrupt_1:
            iter.interrupt_1 = false;
            iter.cur = iter.cur.right;
        }
        else {
            // 在当前节点的左子树中最大（最右侧）节点
            iter.mr = iter.cur.left;
            while (is_not_nil(iter.mr.right) && iter.mr.right != iter.cur) iter.mr = iter.mr.right;

            // 如果左子树中最大（最右侧）节点没有右子树，则认为访问到这一节点时，应该返回到这左子树的父节点
            if (is_nil(iter.mr.right)) {
                // 建立线索
                iter.mr.right = iter.cur;
                iter.cur = iter.cur.left;
            }
            else {
                // 如果当前节点左子树最大（最右侧）节点存在右子树（即已经建立索引），则说明应遍历当前节点
                iter.interrupt_2 = true;
                return;

                // 遍历右子树
travel_interrupt_2:
                iter.interrupt_2 = false;
                iter.cur = iter.mr.right;
                iter.mr.right = nil;
                iter.cur = iter.cur.right;
            }
        }
    }
}
```

需要说明的是，我们有一个清空`morris_link`的操作，因此在for循环里不能使用`break`命令跳出循环，否则下次循环时出现异常
