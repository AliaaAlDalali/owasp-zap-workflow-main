"""Expected business failures raised by services.

They carry a message a user can read; main.py turns each kind into the matching
HTTP status with a {"message": ...} body, so services stay free of HTTP details.
"""


class AppError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class NotFoundError(AppError):
    pass


class PermissionDeniedError(AppError):
    pass


class ConflictError(AppError):
    pass


class RuleViolationError(AppError):
    """The request is well-formed but breaks a business rule."""


class AuthenticationError(AppError):
    pass


class TooManyAttemptsError(AppError):
    pass
