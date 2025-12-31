from django.db import models
from django.contrib.auth.models import User

# ✅ EXISTING MODEL (you MUST have this)
class Expense(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.FloatField()
    category = models.CharField(max_length=50)
    description = models.CharField(max_length=255, blank=True)
    date = models.DateField()

    def __str__(self):
        return f"{self.user.username} - {self.amount}"


# ✅ NEW MODEL (permission system)
class UserPermission(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=50)

    class Meta:
        unique_together = ("user", "code")

    def __str__(self):
        return f"{self.user.username} → {self.code}"
