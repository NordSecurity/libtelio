#if SWIGGO
%go_import("unsafe")

%insert(go_wrapper) %{
var eventCallbacks = map[uintptr]func(string){}
var loggerCallbacks = map[uintptr]func(int, string){}
// Note: This can only ensure enough place for 8 callbacks
// Application can crash when creating more if these the last
// items on stack
// The real fix for this would be to avoid using pointers where not necessary. In this case - key to hashmap
var arbitraryValue = uint64(0)
var arbitraryAddress = uintptr(unsafe.Pointer(&arbitraryValue))

func maxEventCbIndex() uintptr {
        maxI := arbitraryAddress
        for i := range eventCallbacks {
                if i > maxI {
                        maxI = i
                }
        }
        return maxI
}

func maxLoggerCbIndex() uintptr {
        maxI := arbitraryAddress
        for i := range loggerCallbacks {
                if i > maxI {
                        maxI = i
                }
        }
        return maxI
}
%}

%typemap(gotype) telio_event_cb "func(string)";
%typemap(imtype) telio_event_cb "C.telio_event_cb";
%typemap(goin) telio_event_cb {
        index := maxEventCbIndex() + 1
        cb := C.telio_event_cb{
                ctx: unsafe.Pointer(index),
                cb: (C.telio_event_fn)(C.call_telio_event_cb),
        }
        eventCallbacks[index] = $input
        $result = cb
}
%typemap(in) telio_event_cb {
        $1 = $input;
}

%typemap(goout) (struct telio*) {
        if $input == SwigcptrTelio(0) {
                $result = nil
        } else {
                $result = $input
        }
}

%insert(go_wrapper) %{
//export call_telio_event_cb
func call_telio_event_cb(ctx uintptr, str *C.char) {
        if callback, ok := eventCallbacks[ctx]; ok {
                callback(C.GoString(str))
        }
}
%}


%typemap(gotype) telio_logger_cb "func(int, string)";
%typemap(imtype) telio_logger_cb "C.telio_logger_cb";
%typemap(goin) telio_logger_cb {
        index := maxLoggerCbIndex() + 1
        cb := C.telio_logger_cb{
                ctx: unsafe.Pointer(index),
                cb: (C.telio_logger_fn)(C.call_telio_logger_cb),
        }
        loggerCallbacks[index] = $input
        $result = cb
}
%typemap(in) telio_logger_cb {
        $1 = $input;
}

%insert(go_wrapper) %{
//export call_telio_logger_cb
func call_telio_logger_cb(ctx uintptr, level C.int, str *C.char) {
        if callback, ok := loggerCallbacks[ctx]; ok {
                callback(int(level), C.GoString(str))
        }
}
%}
#endif
