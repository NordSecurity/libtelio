import Pyro5.api  # type: ignore


def init_serialization(libtelio):
    TYPES_TO_SERIALIZE = (
        libtelio.Features,
        libtelio.FeatureWireguard,
        libtelio.FeaturePersistentKeepalive,
        libtelio.FeatureNurse,
        libtelio.FeatureQoS,
        libtelio.FeatureLana,
        libtelio.FeaturePaths,
        libtelio.FeatureDirect,
        libtelio.FeatureSkipUnresponsivePeers,
        libtelio.FeatureEndpointProvidersOptimization,
        libtelio.FeatureDerp,
        libtelio.FeatureFirewall,
        libtelio.FeaturePostQuantumVpn,
        libtelio.FeatureLinkDetection,
        libtelio.FeatureDns,
        libtelio.FeatureExitDns,
        libtelio.FeaturePmtuDiscovery,
    )

    def serialize_obj(obj):
        if isinstance(obj, TYPES_TO_SERIALIZE):
            class_name = type(obj).__name__
            return {
                "__class__": f"uniffi.telio_bindings.{class_name}",
                "__dict__": {k: serialize_obj(v) for k, v in obj.__dict__.items()},
            }
        return obj

    def deserialize_obj(class_name, data):
        if isinstance(data, dict) and "__class__" in data and "__dict__" in data:
            class_name = data["__class__"].replace("uniffi.telio_bindings.", "")
            cls = getattr(libtelio, class_name)
            obj = cls.__new__(cls)
            obj.__dict__.update(
                {k: deserialize_obj("", v) for k, v in data["__dict__"].items()}
            )
            return obj
        return data

    for tts in TYPES_TO_SERIALIZE:
        Pyro5.api.register_class_to_dict(tts, serialize_obj)
        class_name = f"uniffi.telio_bindings.{tts.__name__}"
        Pyro5.api.register_dict_to_class(class_name, deserialize_obj)
