"""Phone OTP service."""

import logging
from typing import Optional, Tuple

from django.core.exceptions import ValidationError
from django.utils import timezone

from drf_auth_package import conf
from drf_auth_package.models import PhoneOTP, User
from drf_auth_package.utils.tokens import create_phone_otp
from drf_auth_package.utils.validators import validate_phone_number

logger = logging.getLogger(__name__)


class PhoneService:
    """Service for phone number verification and authentication."""

    @staticmethod
    def send_otp(phone_number: str, user: Optional[User] = None) -> Tuple[bool, str]:
        """
        Generate and send an OTP to a phone number.

        In production, integrate with an SMS provider (Twilio, AWS SNS, etc.).
        This is a placeholder implementation.

        Args:
            phone_number: The phone number to send OTP to.
            user: Optional user associated with the phone number.

        Returns:
            Tuple of (success: bool, message: str).
        """
        try:
            # Validate phone number
            validate_phone_number(phone_number)

            # Generate OTP
            otp, expiry = create_phone_otp(phone_number)

            # Invalidate any previous OTPs for this phone number
            PhoneOTP.objects.filter(
                phone_number=phone_number,
                verified=False
            ).update(verified=True)  # Mark as used

            # Create new OTP record
            phone_otp = PhoneOTP.objects.create(
                user=user,
                phone_number=phone_number,
                otp=otp,
                expires_at=expiry,
            )

            # TODO: Integrate with SMS provider
            # Example: send_sms(phone_number, f"Your OTP is: {otp}")
            logger.info(f"OTP generated for phone {phone_number}: {otp} (THIS IS FOR DEV ONLY)")

            # In production, don't return the OTP in the message
            if conf.get_setting("DEBUG", False):
                return True, f"OTP sent successfully. [DEV MODE: OTP is {otp}]"
            else:
                return True, "OTP sent successfully."

        except ValidationError as e:
            logger.warning(f"Invalid phone number: {phone_number}")
            return False, str(e)
        except Exception as e:
            logger.error(f"Error sending OTP to {phone_number}: {e}")
            return False, "Failed to send OTP. Please try again."

    @staticmethod
    def verify_otp(phone_number: str, otp: str) -> Tuple[bool, Optional[User], str]:
        """
        Verify an OTP for a phone number.

        Args:
            phone_number: The phone number.
            otp: The OTP to verify.

        Returns:
            Tuple of (success: bool, user: Optional[User], message: str).
        """
        try:
            # Find the most recent unverified OTP for this phone number
            phone_otp = PhoneOTP.objects.filter(
                phone_number=phone_number,
                verified=False
            ).order_by('-created_at').first()

            if not phone_otp:
                logger.warning(f"No OTP found for phone {phone_number}")
                return False, None, "No OTP found for this phone number."

            # Increment attempts
            phone_otp.attempts += 1
            phone_otp.save()

            # Check if OTP is still valid
            if not phone_otp.is_valid():
                if phone_otp.attempts >= conf.PHONE_OTP_MAX_ATTEMPTS:
                    logger.warning(f"Max OTP attempts reached for phone {phone_number}")
                    return False, None, "Maximum verification attempts exceeded. Please request a new OTP."
                elif timezone.now() >= phone_otp.expires_at:
                    logger.warning(f"Expired OTP for phone {phone_number}")
                    return False, None, "OTP has expired. Please request a new one."
                else:
                    logger.warning(f"Invalid OTP state for phone {phone_number}")
                    return False, None, "Invalid OTP."

            # Verify OTP
            if phone_otp.otp != otp:
                logger.warning(f"Incorrect OTP for phone {phone_number}")
                remaining = conf.PHONE_OTP_MAX_ATTEMPTS - phone_otp.attempts
                return False, None, f"Incorrect OTP. {remaining} attempts remaining."

            # Mark OTP as verified
            phone_otp.verified = True
            phone_otp.save()

            # Get or update user
            user = phone_otp.user
            if user:
                # Update user's phone verification status
                user.phone_verified = True
                user.save()
                logger.info(f"Phone {phone_number} verified for user {user.email}")
            else:
                # Try to find user by phone number
                try:
                    user = User.objects.get(phone_number=phone_number)
                    user.phone_verified = True
                    user.save()
                    logger.info(f"Phone {phone_number} verified for existing user {user.email}")
                except User.DoesNotExist:
                    logger.info(f"Phone {phone_number} verified but no user associated")

            return True, user, "Phone number verified successfully."

        except Exception as e:
            logger.error(f"Error verifying OTP for {phone_number}: {e}")
            return False, None, "Failed to verify OTP. Please try again."

    @staticmethod
    def phone_login(phone_number: str, otp: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user using phone number and OTP.

        Args:
            phone_number: The phone number.
            otp: The OTP to verify.

        Returns:
            Tuple of (success: bool, user: Optional[User], message: str).
        """
        success, user, message = PhoneService.verify_otp(phone_number, otp)

        if success and user:
            logger.info(f"User {user.email} logged in via phone number")
            return True, user, "Login successful."
        elif success and not user:
            return False, None, "Phone verified but no user account found. Please register first."
        else:
            return False, None, message

    @staticmethod
    def link_phone_to_user(user: User, phone_number: str) -> Tuple[bool, str]:
        """
        Link a phone number to a user account.

        Args:
            user: The user to link the phone to.
            phone_number: The phone number to link.

        Returns:
            Tuple of (success: bool, message: str).
        """
        try:
            validate_phone_number(phone_number)

            # Check if phone is already in use
            if User.objects.filter(phone_number=phone_number).exclude(id=user.id).exists():
                return False, "This phone number is already associated with another account."

            user.phone_number = phone_number
            user.phone_verified = False  # Will be verified after OTP verification
            user.save()

            logger.info(f"Phone {phone_number} linked to user {user.email}")
            return True, "Phone number linked successfully. Please verify it."

        except ValidationError as e:
            return False, str(e)
        except Exception as e:
            logger.error(f"Error linking phone to user {user.email}: {e}")
            return False, "Failed to link phone number. Please try again."
