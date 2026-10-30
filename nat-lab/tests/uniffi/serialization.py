# mypy: ignore-errors
import enum
import inspect
import Pyro5.api  # type: ignore


# This function sets up serialization and deserialization for all public classes and enums in a module
#
# A module is passed as a parameter, and then all public classes and enums are extracted from that module
# Functions are then defined to recursively (de)serialize all of those types to and from python dicts
# Finally, the (de)serialier functions are registered as Pyro5 (de)serializers for all of the relevant types
#
# This function needs to be called once per session to work.
# For natlab, that means it has to be called both on the test host and on the container/VM,
# which can be represented by libtelio_proxy.py and libtelio_remote.py, respectively.
def init_serialization(libtelio):
    all_members = inspect.getmembers(libtelio, inspect.isclass)
    public_members = []
    for name, cls_obj in all_members:
        if cls_obj.__module__ == libtelio.__name__ and not name.startswith("_"):
            public_members.append(cls_obj)
            nested_members = inspect.getmembers(cls_obj, inspect.isclass)
            for nested_name, nested_cls_obj in nested_members:
                if (
                    nested_cls_obj.__module__ == libtelio.__name__
                    and not nested_name.startswith("_")
                ):
                    public_members.append(nested_cls_obj)

    enums = []
    other_classes = []

    for member_cls in public_members:
        if issubclass(member_cls, enum.Enum):
            enums.append(member_cls)
        else:
            other_classes.append(member_cls)

    enums = tuple(enums)
    safe_classes_for_isinstance = []

    for cls_to_check in other_classes:
        is_protocol = getattr(cls_to_check, "_is_protocol", False)
        is_runtime_protocol = getattr(cls_to_check, "_is_runtime_protocol", False)

        if is_protocol and not is_runtime_protocol:
            pass
        else:
            safe_classes_for_isinstance.append(cls_to_check)

    classes = tuple(safe_classes_for_isinstance)

    def serialize_obj(obj):
        if obj is None or isinstance(obj, (str, int, float, bool, bytes)):
            return obj
        if isinstance(obj, list):
            return [serialize_obj(x) for x in obj]
        if isinstance(obj, dict):
            return {str(k): serialize_obj(v) for k, v in obj.items()}
        if isinstance(obj, classes):
            class_name = type(obj).__name__
            dict_to_serialize = {}
            if hasattr(obj, "__dict__"):
                dict_to_serialize = obj.__dict__
            else:
                print(
                    f"Warning: Object of class {class_name} is in 'classes' but has no __dict__ for serialization."
                )

            out = {
                "__class__": class_name,
                "__dict__": {k: serialize_obj(v) for k, v in dict_to_serialize.items()},
            }
            return out
        if isinstance(obj, enums):
            enum_name = type(obj).__name__
            return {"__enum__": enum_name, "value": obj.name}
        return obj

    def deserialize_obj(class_name, data):
        if isinstance(data, dict):
            if "__class__" in data:
                class_name = data["__class__"].split(".")
                cls = libtelio
                for name in class_name:
                    cls = getattr(cls, name)
                obj = cls.__new__(cls)
                obj.__dict__.update(
                    {k: deserialize_obj("", v) for k, v in data["__dict__"].items()}
                )
                return obj
            if "__enum__" in data:
                enum_name = data["__enum__"]
                enum_class = getattr(libtelio, enum_name)
                return enum_class[data["value"]]
        if isinstance(data, list):
            return [deserialize_obj(class_name, x) for x in data]
        return data

    for tts in classes + enums:
        Pyro5.api.register_class_to_dict(tts, serialize_obj)
        class_name = tts.__name__
        Pyro5.api.register_dict_to_class(class_name, deserialize_obj)

    # -------------------------------------------------------------------------
    # ConnectionConfig cross-process serialization
    #
    # Builder classes are uniffi opaque objects wrapping a process-local Rust
    # Arc pointer that cannot cross the Pyro5 wire.  Instead, every call on a
    # builder (including __init__) is recorded in _call_log as a
    # (method_name, args) tuple.  ConnectionConfig is serialized from that log
    # and deserialized by replaying it against a fresh builder in the remote
    # process.  Adding new builder methods requires no changes here.
    # -------------------------------------------------------------------------

    def _patch_builder(builder_cls):
        """Record every __init__ / setter / build() call in _call_log."""

        if getattr(builder_cls, "_call_log_patched", False):
            return
        builder_cls._call_log_patched = True  # pylint: disable=protected-access

        orig_init = builder_cls.__init__
        cls_name = builder_cls.__name__

        def _init(self, *args):
            orig_init(self, *args)
            self._call_log = [(cls_name, args)]  # pylint: disable=protected-access

        builder_cls.__init__ = _init

        for method_name in list(vars(builder_cls)):
            if method_name.startswith("_"):
                continue
            orig = getattr(builder_cls, method_name)

            def _wrap(orig=orig, method_name=method_name):
                def wrapper(self, *args):
                    result = orig(self, *args)
                    # pylint: disable=protected-access
                    result._call_log = list(self._call_log) + [(method_name, args)]
                    # pylint: enable=protected-access
                    return result

                return wrapper

            setattr(builder_cls, method_name, _wrap())

    _patch_builder(libtelio.VpnConnectionConfigBuilder)
    _patch_builder(libtelio.MeshnetConnectionConfigBuilder)

    # --- ConnectionConfig custom Pyro5 serializer/deserializer ---------------

    def _serialize_connection_config(obj):
        call_log = getattr(obj, "_call_log", None)
        if call_log is None:
            raise ValueError(
                "ConnectionConfig._call_log is missing; build it via a "
                "VpnConnectionConfigBuilder or MeshnetConnectionConfigBuilder "
                "after init_serialization() has run."
            )
        return {
            "__class__": "ConnectionConfig",
            "__dict__": {"_call_log": serialize_obj(call_log)},
        }

    def _deserialize_connection_config(_class_name, data):
        call_log = data["__dict__"]["_call_log"]
        cls_name, init_args = call_log[0]
        builder = getattr(libtelio, cls_name)(
            *[deserialize_obj("", a) for a in init_args]
        )
        for method_name, args in call_log[1:]:
            builder = getattr(builder, method_name)(
                *[deserialize_obj("", a) for a in args]
            )
        return builder

    Pyro5.api.register_class_to_dict(
        libtelio.ConnectionConfig, _serialize_connection_config
    )
    Pyro5.api.register_dict_to_class("ConnectionConfig", _deserialize_connection_config)
