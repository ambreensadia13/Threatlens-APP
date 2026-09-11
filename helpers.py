import socket
import ipaddress
from urllib.parse import urlparse, quote
import requests


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target, target_type):

    if not target:
        return False, "Please enter a target."

    target = target.strip()

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if target_type == "IP":

        try:
            ipaddress.ip_address(target)
            return True, ""

        except ValueError:
            return False, "Invalid IP address."

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    if target_type == "Domain":

        if "://" in target:
            return False, (
                "Enter only the domain, for example: example.com"
            )

        if " " in target:
            return False, "Domain cannot contain spaces."

        if "." not in target:
            return False, "Please enter a valid domain."

        return True, ""

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if target_type == "URL":

        try:

            parsed = urlparse(target)

            if parsed.scheme not in ["http", "https"]:
                return False, (
                    "URL must start with http:// or https://"
                )

            if not parsed.netloc:
                return False, "Invalid URL."

            if not parsed.hostname:
                return False, "Invalid URL hostname."

            return True, ""

        except Exception:
            return False, "Invalid URL."

    return False, "Unknown target type."


# ============================================================
# ALIENVAULT OTX
# ============================================================

def get_otx(target, target_type, api_key):

    result = {
        "source": "AlienVault OTX",
        "status": "error"
    }

    if not api_key:

        result["message"] = "OTX API key not provided."
        return result

    try:

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        if target_type == "IP":

            url = (
                "https://otx.alienvault.com/api/v1/"
                "indicators/IPv4/"
                + target
                + "/general"
            )

        # ----------------------------------------------------
        # DOMAIN
        # ----------------------------------------------------

        elif target_type == "Domain":

            url = (
                "https://otx.alienvault.com/api/v1/"
                "indicators/domain/"
                + target
                + "/general"
            )

        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        elif target_type == "URL":

            encoded = quote(target, safe="")

            url = (
                "https://otx.alienvault.com/api/v1/"
                "indicators/url/"
                + encoded
                + "/general"
            )

        else:

            result["message"] = "Unsupported target type."
            return result

        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=20
        )

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        if response.status_code == 200:

            try:
                data = response.json()

            except Exception:
                data = {}

            result["status"] = "success"
            result["data"] = data

            return result

        # ----------------------------------------------------
        # INVALID API KEY
        # ----------------------------------------------------

        if response.status_code in [401, 403]:

            result["message"] = "OTX API key was rejected."
            return result

        # ----------------------------------------------------
        # NO INFORMATION
        # ----------------------------------------------------

        if response.status_code == 404:

            result["status"] = "success"
            result["message"] = "No intelligence found."
            result["data"] = {}

            return result

        # ----------------------------------------------------
        # OTHER HTTP ERROR
        # ----------------------------------------------------

        result["message"] = (
            "OTX returned HTTP "
            + str(response.status_code)
        )

        return result

    except requests.exceptions.Timeout:

        result["message"] = "OTX request timed out."
        return result

    except requests.exceptions.RequestException as e:

        result["message"] = (
            "OTX connection error: "
            + str(e)
        )

        return result

    except Exception as e:

        result["message"] = (
            "Unexpected OTX error: "
            + str(e)
        )

        return result


# ============================================================
# DNS / HOST INFORMATION
# ============================================================

def get_dns(target, target_type):

    result = {
        "source": "DNS / Host",
        "status": "error"
    }

    try:

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        if target_type == "IP":

            try:

                hostname = socket.gethostbyaddr(
                    target
                )[0]

            except Exception:

                hostname = "Not available"

            result["status"] = "success"
            result["target"] = target
            result["hostname"] = hostname

            return result

        # ----------------------------------------------------
        # DOMAIN
        # ----------------------------------------------------

        if target_type == "Domain":

            hostname = target

        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        elif target_type == "URL":

            parsed = urlparse(target)
            hostname = parsed.hostname

            if not hostname:

                result["message"] = (
                    "Could not extract hostname."
                )

                return result

        else:

            result["message"] = (
                "Unsupported target type."
            )

            return result

        # ----------------------------------------------------
        # DNS RESOLUTION
        # ----------------------------------------------------

        ip = socket.gethostbyname(
            hostname
        )

        result["status"] = "success"
        result["hostname"] = hostname
        result["resolved_ip"] = ip

        return result

    except socket.gaierror:

        result["status"] = "success"
        result["message"] = (
            "Hostname could not be resolved."
        )

        return result

    except Exception as e:

        result["message"] = str(e)

        return result


# ============================================================
# COLLECT INTELLIGENCE
# ============================================================

def collect_intelligence(
    target,
    target_type,
    otx_api_key
):

    results = {}

    # AlienVault OTX
    results["AlienVault OTX"] = get_otx(
        target,
        target_type,
        otx_api_key
    )

    # DNS / Host
    results["DNS / Host"] = get_dns(
        target,
        target_type
    )

    return results
