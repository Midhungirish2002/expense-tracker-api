VIEW_EXPENSE = "view_expense"
CREATE_EXPENSE = "create_expense"
EDIT_EXPENSE = "edit_expense"
DELETE_EXPENSE = "delete_expense"
VIEW_REPORTS = "view_reports"
from tracker.permission_codes import VIEW_REPORTS

if not has_permission(request.user, VIEW_REPORTS):
    raise PermissionDenied("permission denied")
