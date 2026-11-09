"""Tunable lifetimes and identifiers, resolved from `OAN Auth Settings` and site_config.json.

Exposed as functions rather than module constants on purpose: settings are
re-read at runtime, and a constant bound at import time would pin whatever the
value happened to be when the worker booted. A TTL you cannot change without a
process restart is a TTL nobody changes during an incident.

Login and registration policy lives on the `OAN Auth Settings` DocType. A field
left blank falls back to its site_config.json key, then to the default below, so
a site configured before the DocType existed keeps its values:

    "jwt_access_token_ttl": 900,
    "jwt_refresh_token_ttl": 2592000,
    "jwt_refresh_token_ttl_remember_me": 7776000,
    "password_reset_otp_ttl": 600,
    "password_reset_otp_length": 6,
    "password_reset_otp_max_attempts": 5,
    "password_reset_otp_max_issued_per_day": 5,
    "jwt_default_registration_role": "Customer",
    "jwt_self_registerable_roles": []

Deployment values are read from site_config.json only, all optional:

    "jwt_issuer": "oan-auth",
    "service_prefix": "A2C"

Login delegated to the OpenG2P IAM service is not configured here: each login
option is a row of the `OAN IAM Service` DocType, read through `iam_services()`
below. See api/iam_tokens.py and api/iam_users.py.
"""

import frappe
from frappe.utils import cint

AUTH_SETTINGS_DOCTYPE = "OAN Auth Settings"
SELF_REGISTERABLE_ROLE_DOCTYPE = "OAN Self Registerable Role"


def _stored_setting(field: str) -> str | None:
	# Reads the stored rows and not the DocType's meta, so a request served between a
	# code deploy and its `bench migrate` still works, on the site_config value.
	return frappe.db.get_singles_dict(AUTH_SETTINGS_DOCTYPE).get(field)


def _int_setting(field: str, conf_key: str, default: int) -> int:
	"""The `OAN Auth Settings` field, else the site_config key, else `default`. Zero counts as blank."""
	return cint(_stored_setting(field)) or int(frappe.conf.get(conf_key) or default)


# Short by design. The access token carries a roles claim, and a claim is a
# snapshot: it stops reflecting reality the moment roles change. The TTL is the
# window in which a revoked role is still believed, so it buys staleness with
# every second it grows. Fifteen minutes keeps that window smaller than the time
# it takes a human to notice and act on a bad grant.
DEFAULT_ACCESS_TOKEN_TTL = 15 * 60

DEFAULT_REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60
DEFAULT_REFRESH_TOKEN_TTL_REMEMBER_ME = 90 * 24 * 60 * 60


def access_token_ttl() -> int:
	"""Lifetime in seconds of a newly issued access token."""
	return _int_setting("access_token_ttl", "jwt_access_token_ttl", DEFAULT_ACCESS_TOKEN_TTL)


def refresh_token_ttl(remember_me: bool = False) -> int:
	"""Lifetime in seconds of a newly issued refresh token."""
	if remember_me:
		return _int_setting(
			"refresh_token_ttl_remember_me",
			"jwt_refresh_token_ttl_remember_me",
			DEFAULT_REFRESH_TOKEN_TTL_REMEMBER_ME,
		)
	return _int_setting("refresh_token_ttl", "jwt_refresh_token_ttl", DEFAULT_REFRESH_TOKEN_TTL)


# A phone-only account cannot be sent a reset link, so it is sent a numeric code
# instead. Six digits is only ~20 bits, which is why the two settings below
# exist at all: the code is worth guessing unless its lifetime is short and the
# number of guesses is capped. Ten minutes is long enough to survive slow SMS
# delivery on a rural network and short enough that an unused code is not left
# standing.
DEFAULT_PASSWORD_RESET_OTP_TTL = 10 * 60
DEFAULT_PASSWORD_RESET_OTP_LENGTH = 6

# Five wrong guesses burns the code entirely rather than merely rejecting the
# attempt, so an attacker cannot keep working through the keyspace by retrying.
# The cost of getting this wrong is a legitimate user requesting a new code.
DEFAULT_PASSWORD_RESET_OTP_MAX_ATTEMPTS = 5

# Codes texted to one account per day. Counted per resolved user and never reset
# by issuing a code, so requesting fresh codes cannot refill the guess budget or
# flood the owner's phone.
DEFAULT_PASSWORD_RESET_OTP_MAX_ISSUED_PER_DAY = 5


def password_reset_otp_ttl() -> int:
	"""Seconds a password-reset OTP stays valid."""
	return _int_setting("password_reset_otp_ttl", "password_reset_otp_ttl", DEFAULT_PASSWORD_RESET_OTP_TTL)


def password_reset_otp_length() -> int:
	"""Number of digits in a password-reset OTP."""
	return _int_setting(
		"password_reset_otp_length", "password_reset_otp_length", DEFAULT_PASSWORD_RESET_OTP_LENGTH
	)


def password_reset_otp_max_attempts() -> int:
	"""Wrong guesses allowed against one OTP before it is destroyed."""
	return _int_setting(
		"password_reset_otp_max_attempts",
		"password_reset_otp_max_attempts",
		DEFAULT_PASSWORD_RESET_OTP_MAX_ATTEMPTS,
	)


def password_reset_otp_max_issued_per_day() -> int:
	"""Password-reset OTPs one account may be sent in 24 hours."""
	return _int_setting(
		"password_reset_otp_max_issued_per_day",
		"password_reset_otp_max_issued_per_day",
		DEFAULT_PASSWORD_RESET_OTP_MAX_ISSUED_PER_DAY,
	)


def issuer() -> str:
	"""The `iss` claim, and the value verification demands.

	Defaults to the site name, which makes tokens from a staging site fail
	closed against production rather than being silently accepted — the two
	share code and could otherwise share a secret by deployment accident.
	"""
	return frappe.conf.get("jwt_issuer") or frappe.local.site


def self_registerable_roles() -> list[str]:
	"""List of roles permitted for self-registration by guest callers."""
	roles = []
	# Checked first, not caught: on Postgres a failed query would abort the transaction.
	if frappe.db.table_exists(SELF_REGISTERABLE_ROLE_DOCTYPE):
		roles = frappe.get_all(
			SELF_REGISTERABLE_ROLE_DOCTYPE,
			filters={"parenttype": AUTH_SETTINGS_DOCTYPE, "parent": AUTH_SETTINGS_DOCTYPE},
			pluck="role",
			order_by="idx asc",
		)
	return roles or list(frappe.conf.get("jwt_self_registerable_roles") or [])


def default_registration_role() -> str | None:
	"""The role a registration that names none is given, if one is configured."""
	return _stored_setting("default_registration_role") or frappe.conf.get("jwt_default_registration_role")


def name_in_scope(name: str, prefixes: tuple[str, ...]) -> bool:
	"""Whether `name` is a prefix itself or starts with a prefix and a space (`A2C Lead`, not `A2Cfoo`)."""
	return any(name == p or name.startswith(f"{p} ") for p in prefixes)


def service_prefixes() -> tuple[str, ...]:
	"""Bare name prefixes of the roles and doctypes this deployment's services own, e.g. `("A2C",)`.

	The admin endpoints expose only roles, doctypes and users matching one. A
	consuming app declares its prefix with the `oan_service_prefix` hook; the
	`service_prefix` site config key (a string or list) takes precedence.
	"""
	configured = frappe.conf.get("service_prefix")
	if isinstance(configured, str):
		configured = [configured]
	values = configured or frappe.get_hooks("oan_service_prefix")
	return tuple(dict.fromkeys(v.strip() for v in values if v and v.strip()))


IAM_SERVICE_DOCTYPE = "OAN IAM Service"
IAM_SERVICES_CACHE_KEY = "oan_auth:iam_services"
# The row key reserved for this app's own username and password login.
LOCAL_LOGIN_KEY = "local"

_IAM_SERVICE_FIELDS = (
	"key",
	"label",
	"icon",
	"sort_order",
	"base_url",
	"provider_id",
	"issuer",
	"client_id",
	"application",
	"cookie_prefix",
	"post_logout_redirect_uri",
	"userinfo_url",
	"jwks_url",
	"request_timeout",
)


def iam_services() -> list[frappe._dict]:
	"""Enabled login options (`OAN IAM Service` rows) in `sort_order`.

	Cached until a row changes (the DocType clears the cache on save and
	delete), so token validation costs no query per request. Each entry carries
	its `default_roles` as a plain list.
	"""
	services = frappe.cache.get_value(IAM_SERVICES_CACHE_KEY)
	if services is None:
		services = _load_iam_services()
		frappe.cache.set_value(IAM_SERVICES_CACHE_KEY, services)
	return [frappe._dict(s) for s in services]


def _load_iam_services() -> list[dict]:
	# Not bank-scoped or otherwise permission-filtered: this is server-side
	# configuration, read on behalf of every request, guests included.
	rows = frappe.get_all(
		IAM_SERVICE_DOCTYPE,
		filters={"enabled": 1},
		fields=list(_IAM_SERVICE_FIELDS),
		order_by="sort_order asc, name asc",
	)
	if not rows:
		return []

	names = [r.key for r in rows]
	roles: dict[str, list[str]] = {}
	for d in frappe.get_all(
		"OAN IAM Service Role",
		filters={"parenttype": IAM_SERVICE_DOCTYPE, "parent": ("in", names)},
		fields=["parent", "role"],
		order_by="idx asc",
	):
		roles.setdefault(d.parent, []).append(d.role)

	return [
		{
			**{f: r.get(f) for f in _IAM_SERVICE_FIELDS},
			"base_url": (r.base_url or "").rstrip("/"),
			"cookie_prefix": r.cookie_prefix or "",
			"post_logout_redirect_uri": r.post_logout_redirect_uri or "",
			"userinfo_url": r.userinfo_url or "",
			"jwks_url": r.jwks_url or "",
			"default_roles": roles.get(r.key, []),
		}
		for r in rows
	]


def clear_iam_services_cache() -> None:
	frappe.cache.delete_value(IAM_SERVICES_CACHE_KEY)


def iam_service(key: str | None = None) -> frappe._dict | None:
	"""The enabled IAM login option named `key`, or None. Never the `local` row.

	If `key` is None, empty, or 'default', and exactly one IAM option is enabled,
	that option is returned as the default.
	"""
	if not key or key == "default":
		iam_options = [s for s in iam_services() if s.key != LOCAL_LOGIN_KEY]
		if len(iam_options) == 1:
			return iam_options[0]
		return None
	if key == LOCAL_LOGIN_KEY:
		return None
	return next((s for s in iam_services() if s.key == key), None)


def iam_service_for_issuer(iss: str, azp: str | None = None) -> frappe._dict | None:
	"""The enabled IAM login option whose `issuer` is exactly `iss`, or None.

	When multiple options share the same issuer, `azp` (client_id) disambiguates.
	"""
	if not iss:
		return None
	candidates = [s for s in iam_services() if s.key != LOCAL_LOGIN_KEY and s.issuer == iss]
	if not candidates:
		return None
	if azp:
		for s in candidates:
			if s.client_id == azp:
				return s
	for s in candidates:
		if not s.client_id:
			return s
	return candidates[0]
