import inspect
import Pyro5.api  # type: ignore


def init_serialization(libtelio):
    all_members = inspect.getmembers(libtelio, inspect.isclass)
    public_members = []
    for name, cls in all_members:
        if not name.startswith("_"):
            public_members.append(cls)
            nested_members = inspect.getmembers(cls, inspect.isclass)
            for name, cls in nested_members:
                if not name.startswith("_"):
                    public_members.append(cls)

    classes = tuple(
        filter(
            lambda m: str(m).startswith("<class ") and libtelio.__name__ in str(m),
            public_members,
        )
    )
    enums = tuple(filter(lambda m: str(m).startswith("<enum "), public_members))

    def serialize_obj(obj):
        if isinstance(obj, classes):
            class_name = type(obj).__name__
            out = {
                "__class__": class_name,
                "__dict__": {k: serialize_obj(v) for k, v in obj.__dict__.items()},
            }
            return out
        if isinstance(obj, enums):
            enum_name = type(obj).__name__
            return {"__enum__": enum_name, "value": obj.name}
        if isinstance(obj, list):
            return [serialize_obj(x) for x in obj]
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
