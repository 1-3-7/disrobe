struct Base {
    int tag = 0;
    virtual int kind() const CXX_KEY;
    virtual int rank() const { return 1; }
    virtual ~Base() {}
};

struct Derived : Base {
    int kind() const override CXX_KEY;
    int rank() const override { return 2; }
    virtual int extra() const { return 9; }
};

struct Left {
    virtual int left_id() const CXX_KEY;
    virtual ~Left() {}
};

struct Right {
    virtual int right_id() const CXX_KEY;
    virtual ~Right() {}
};

struct Multi : Left, Right {
    int left_id() const override { return 11; }
    int right_id() const override { return 21; }
};

struct VBase {
    int shared = 0;
    virtual int vsound() const CXX_KEY;
    virtual ~VBase() {}
};

struct VLeft : virtual VBase {
    int vsound() const override { return 101; }
};

struct VRight : virtual VBase {
    int vsound() const override { return 102; }
};

struct VDiamond : VLeft, VRight {
    int vsound() const override CXX_KEY;
};

#if defined(CXX_DEFS)

int Base::kind() const { return 0; }
int Derived::kind() const { return 1; }
int Left::left_id() const { return 10; }
int Right::right_id() const { return 20; }
int VBase::vsound() const { return 100; }
int VDiamond::vsound() const { return 103; }

Base *make_base(int s) { return s & 1 ? static_cast<Base *>(new Derived()) : new Base(); }
Left *make_left(int s) { (void)s; return static_cast<Left *>(new Multi()); }
VBase *make_vbase(int s) { (void)s; return static_cast<VBase *>(new VDiamond()); }

#elif defined(CXX_MAIN)

#include <cstdio>
#include <typeinfo>

Base *make_base(int s);
Left *make_left(int s);
VBase *make_vbase(int s);

int main(int argc, char **argv) {
    (void)argv;
    Base *b = make_base(argc);
    Left *l = make_left(argc);
    VBase *v = make_vbase(argc);
    int acc = b->kind() + b->rank() + l->left_id() + v->vsound();
    if (auto *d = dynamic_cast<Derived *>(b)) acc += d->extra();
    if (auto *m = dynamic_cast<Multi *>(l)) acc += m->right_id();
    if (auto *vd = dynamic_cast<VDiamond *>(v)) acc += vd->vsound();
    std::printf("%d %s %s %s\n", acc, typeid(*b).name(), typeid(*l).name(), typeid(*v).name());
    return acc & 1;
}

#else

static volatile int sink = 0;

extern "C" int run_hierarchy() {
    Derived d;
    Multi m;
    VDiamond vd;
    Base *bp = &d;
    Left *lp = &m;
    Right *rp = &m;
    VBase *vbp = &vd;
    sink += bp->kind() + bp->rank() + d.extra();
    sink += lp->left_id() + rp->right_id();
    sink += vbp->vsound();
    return sink;
}

int Base::kind() const { return 0; }
int Derived::kind() const { return 1; }
int Left::left_id() const { return 10; }
int Right::right_id() const { return 20; }
int VBase::vsound() const { return 100; }
int VDiamond::vsound() const { return 103; }

#endif
