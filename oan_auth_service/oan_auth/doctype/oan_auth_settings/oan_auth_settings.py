import frappe
from frappe import _
from frappe.model.document import Document

from oan_auth_service.api.iam_users import REFUSED_ROLES


class OANAuthSettings(Document):
	"""Login and registration policy, read through `config/settings.py`."""

	def validate(self):
		roles = {row.role for row in self.self_registerable_roles}
		if self.default_registration_role:
			roles.add(self.default_registration_role)
		refused = sorted(roles & REFUSED_ROLES)
		if refused:
			frappe.throw(
				_("These roles cannot be given through registration: {0}").format(", ".join(refused)),
				frappe.ValidationError,
			)
