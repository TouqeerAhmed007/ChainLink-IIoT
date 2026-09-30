POLICY: dict[str, dict[str, frozenset[str]]] = {
    "temperature_sensor": {"temperature": frozenset({"WRITE"})},
    "pressure_sensor": {"pressure": frozenset({"WRITE"})},
    "smart_meter": {"energy": frozenset({"WRITE"})},
    "camera": {"video": frozenset({"WRITE"})},
    "valve_controller": {"valve": frozenset({"OPEN", "CLOSE", "READ"}),
                         "production_line": frozenset({"STOP"})},
    "motor_controller": {"motor": frozenset({"START", "STOP", "READ"}),
                         "production_line": frozenset({"STOP"})},
}

TELEMETRY: dict[str, str] = {
    "temperature_sensor": "temperature",
    "pressure_sensor": "pressure",
    "smart_meter": "energy",
    "camera": "video",
}


def is_allowed(role, resource, operation, temp: bool = False) -> bool:
    if not isinstance(role, str):
        return False
    if temp:
        return operation == "WRITE" and TELEMETRY.get(role) == resource
    return operation in POLICY.get(role, {}).get(resource, ())
