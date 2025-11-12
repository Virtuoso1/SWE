"""
Fine service for the Library Management System
Handles all fine-related business logic
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from db.repositories import get_repositories
from db.models import Fine

logger = logging.getLogger(__name__)

class FineService:
    """Service class for handling fine operations"""
    
    @staticmethod
    def create_fine(borrow_id: int, amount: float) -> Optional[Dict[str, Any]]:
        """
        Create a new fine for a borrow record
        
        Args:
            borrow_id: ID of the borrow record
            amount: Fine amount
            
        Returns:
            Dict containing fine data if creation successful, None otherwise
        """
        try:
            # Verify borrow record exists
            repos = get_repositories()
            borrow = repos['borrow'].get_by_id(borrow_id)
            if not borrow:
                logger.warning(f"Fine creation failed: Borrow record {borrow_id} not found")
                return None
            
            # Check if fine already exists for this borrow
            repos = get_repositories()
            existing_fines = repos['fine'].get_all()
            for fine in existing_fines:
                if fine.borrow_id == borrow_id and fine.paid_status == 'unpaid':
                    logger.warning(f"Fine creation failed: Unpaid fine already exists for borrow {borrow_id}")
                    return None
            
            # Create fine
            fine = Fine(
                borrow_id=borrow_id,
                amount=amount,
                paid_status='unpaid'
            )
            
            repos = get_repositories()
            fine_id = repos['fine'].create(fine)
            
            if fine_id:
                # Get the created fine
                created_fine = repos['fine'].get_by_id(fine_id)
                if created_fine:
                    logger.info(f"Fine created successfully for borrow {borrow_id}")
                    return created_fine.to_dict()
                else:
                    logger.error(f"Failed to retrieve created fine for borrow {borrow_id}")
                    return None
            else:
                logger.error(f"Failed to create fine for borrow {borrow_id}")
                return None
                
        except Exception as e:
            logger.error(f"Fine creation error: {str(e)}")
            return None
    
    @staticmethod
    def pay_fine(fine_id: int) -> bool:
        """
        Mark a fine as paid
        
        Args:
            fine_id: ID of the fine
            
        Returns:
            bool: True if payment successful, False otherwise
        """
        try:
            # Get fine
            repos = get_repositories()
            fine = repos['fine'].get_by_id(fine_id)
            if not fine:
                logger.warning(f"Fine payment failed: Fine {fine_id} not found")
                return False
            
            if fine.paid_status == 'paid':
                logger.warning(f"Fine payment failed: Fine {fine_id} is already paid")
                return False
            
            # Mark as paid
            repos = get_repositories()
            if repos['fine'].mark_as_paid(fine_id):
                logger.info(f"Fine {fine_id} marked as paid")
                return True
            else:
                logger.error(f"Failed to mark fine {fine_id} as paid")
                return False
                
        except Exception as e:
            logger.error(f"Fine payment error: {str(e)}")
            return False
    
    @staticmethod
    def get_fine_by_id(fine_id: int) -> Optional[Dict[str, Any]]:
        """
        Get fine by ID
        
        Args:
            fine_id: ID of the fine
            
        Returns:
            Dict containing fine data if found, None otherwise
        """
        try:
            repos = get_repositories()
            fine = repos['fine'].get_by_id(fine_id)
            if fine:
                return fine.to_dict()
            return None
        except Exception as e:
            logger.error(f"Get fine error: {str(e)}")
            return None
    
    @staticmethod
    def get_user_fines(user_id: int) -> List[Dict[str, Any]]:
        """
        Get all fines for a user
        
        Args:
            user_id: ID of the user
            
        Returns:
            List of dictionaries containing fine data
        """
        try:
            repos = get_repositories()
            fines = repos['fine'].get_by_user(user_id)
            return [fine.to_dict() for fine in fines]
        except Exception as e:
            logger.error(f"Get user fines error: {str(e)}")
            return []
    
    @staticmethod
    def get_all_fines(paid_status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all fines, optionally filtered by paid status
        
        Args:
            paid_status: Filter by paid status ('paid', 'unpaid')
            
        Returns:
            List of dictionaries containing fine data
        """
        try:
            repos = get_repositories()
            fines = repos['fine'].get_all(paid_status)
            return [fine.to_dict() for fine in fines]
        except Exception as e:
            logger.error(f"Get all fines error: {str(e)}")
            return []
    
    @staticmethod
    def calculate_overdue_fines() -> int:
        """
        Calculate and create fines for overdue books
        
        Returns:
            int: Number of fines created
        """
        try:
            repos = get_repositories()
            # Use the repository method to calculate overdue fines
            fines_created = repos['fine'].calculate_overdue_fines()
            logger.info(f"Created {fines_created} overdue fines")
            return fines_created
        except Exception as e:
            logger.error(f"Calculate overdue fines error: {str(e)}")
            return 0
    
    @staticmethod
    def get_fine_statistics() -> Dict[str, Any]:
        """
        Get fine statistics
        
        Returns:
            Dict containing fine statistics
        """
        try:
            repos = get_repositories()
            all_fines = repos['fine'].get_all()
            unpaid_fines = repos['fine'].get_all('unpaid')
            paid_fines = repos['fine'].get_all('paid')
            
            total_fines = len(all_fines)
            unpaid_count = len(unpaid_fines)
            paid_count = len(paid_fines)
            
            # Calculate total amounts
            total_amount = sum(fine.amount for fine in all_fines if fine.amount)
            unpaid_amount = sum(fine.amount for fine in unpaid_fines if fine.amount)
            paid_amount = sum(fine.amount for fine in paid_fines if fine.amount)
            
            return {
                'total_fines': total_fines,
                'unpaid_fines': unpaid_count,
                'paid_fines': paid_count,
                'total_amount': total_amount,
                'unpaid_amount': unpaid_amount,
                'paid_amount': paid_amount
            }
        except Exception as e:
            logger.error(f"Get fine statistics error: {str(e)}")
            return {
                'total_fines': 0,
                'unpaid_fines': 0,
                'paid_fines': 0,
                'total_amount': 0.0,
                'unpaid_amount': 0.0,
                'paid_amount': 0.0
            }
    
    @staticmethod
    def waive_fine(fine_id: int) -> bool:
        """
        Waive a fine (mark as paid without actual payment)
        
        Args:
            fine_id: ID of the fine
            
        Returns:
            bool: True if waiver successful, False otherwise
        """
        try:
            repos = get_repositories()
            # Get fine
            fine = repos['fine'].get_by_id(fine_id)
            if not fine:
                logger.warning(f"Fine waiver failed: Fine {fine_id} not found")
                return False
            
            if fine.paid_status == 'paid':
                logger.warning(f"Fine waiver failed: Fine {fine_id} is already paid")
                return False
            
            # Waive fine
            if repos['fine'].waive_fine(fine_id):
                logger.info(f"Fine {fine_id} waived")
                return True
            else:
                logger.error(f"Failed to waive fine {fine_id}")
                return False
                
        except Exception as e:
            logger.error(f"Fine waiver error: {str(e)}")
            return False
    
    @staticmethod
    def update_fine_amount(fine_id: int, new_amount: float) -> bool:
        """
        Update fine amount
        
        Args:
            fine_id: ID of the fine
            new_amount: New fine amount
            
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            # Get fine
            repos = get_repositories()
            fine = repos['fine'].get_by_id(fine_id)
            if not fine:
                logger.warning(f"Fine update failed: Fine {fine_id} not found")
                return False
            
            if fine.paid_status == 'paid':
                logger.warning(f"Fine update failed: Fine {fine_id} is already paid")
                return False
            
            if new_amount <= 0:
                logger.warning(f"Fine update failed: Invalid amount {new_amount}")
                return False
            
            # Update fine amount
            if repos['fine'].update_amount(fine_id, new_amount):
                logger.info(f"Fine {fine_id} amount updated to ${new_amount}")
                return True
            else:
                logger.error(f"Failed to update fine {fine_id} amount")
                return False
        except Exception as e:
            logger.error(f"Fine update error: {str(e)}")
            return False