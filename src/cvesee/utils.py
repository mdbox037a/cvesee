def parse_cpe(cpe_string: str) -> (str, str):
    parts = cpe_string.split(":")
    return parts[3], parts[4]
