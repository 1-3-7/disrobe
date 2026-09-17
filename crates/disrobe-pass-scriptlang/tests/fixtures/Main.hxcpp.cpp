#include <hxcpp.h>
#include <hx/Boot.h>

HX_DECLARE_CLASS0(Main)

::String Main_obj::greet(::String name) {
    HX_STACKFRAME(&_hx_pos_greet)
    return ::hx::AddString(HX_("Hello, ", 00), ::hx::AddString(name, HX_("!", 01)));
}

int Main_obj::add(int a, int b) {
    HX_STACKFRAME(&_hx_pos_add)
    return a + b;
}

void Main_obj::main() {
    HX_STACKFRAME(&_hx_pos_main)
    ::haxe::Log_obj::trace(Main_obj::greet(HX_("disrobe", 02)), null());
    ::haxe::Log_obj::trace(Main_obj::add(2, 3), null());
}
