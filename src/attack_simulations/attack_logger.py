"""
Attack Logging and Statistics System
Tracks all attack simulations and maintains detailed records

FILE: attack_logger.py
"""

import time
from collections import defaultdict


class AttackLogger:
    """Professional attack logging and statistics system"""
    
    def __init__(self):
        self.attacks = []
        self.stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'attack_types': defaultdict(int),
            'protection_mechanisms': defaultdict(int)
        }
    
    def log_attack(self, attack_data):
        """Log an attack with full details"""
        attack_record = {
            'timestamp': time.time(),
            'attack_name': attack_data.get('attack_name', 'Unknown'),
            'attack_type': attack_data.get('attack_type', 'Unknown'),
            'success': attack_data.get('success', False),
            'protection': attack_data.get('protection', 'None'),
            'details': attack_data.get('details', {}),
            'technique': attack_data.get('technique', 'N/A'),
            'method': attack_data.get('method', 'N/A')
        }
        
        self.attacks.append(attack_record)
        
        # Update statistics
        self.stats['total_attacks'] += 1
        
        if attack_record['success']:
            self.stats['successful_attacks'] += 1
        else:
            self.stats['failed_attacks'] += 1
        
        self.stats['attack_types'][attack_record['attack_type']] += 1
        
        if attack_record['protection'] != 'None':
            self.stats['protection_mechanisms'][attack_record['protection']] += 1
    
    def get_statistics(self):
        """Get current statistics"""
        return {
            'total_attacks': self.stats['total_attacks'],
            'successful_attacks': self.stats['successful_attacks'],
            'failed_attacks': self.stats['failed_attacks'],
            'unique_attacks': len(set(a['attack_name'] for a in self.attacks)),
            'attack_types': dict(self.stats['attack_types']),
            'protections': dict(self.stats['protection_mechanisms'])
        }
    
    def get_recent_attacks(self, n=5):
        """Get n most recent attacks"""
        return sorted(
            self.attacks,
            key=lambda x: x['timestamp'],
            reverse=True
        )[:n]
    
    def get_attacks_by_type(self, attack_type):
        """Get all attacks of a specific type"""
        return [a for a in self.attacks if a['attack_type'] == attack_type]
    
    def get_success_rate(self):
        """Calculate overall success rate"""
        if self.stats['total_attacks'] == 0:
            return 0.0
        return (self.stats['successful_attacks'] / self.stats['total_attacks']) * 100
    
    def reset_statistics(self):
        """Reset all statistics"""
        self.attacks = []
        self.stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'attack_types': defaultdict(int),
            'protection_mechanisms': defaultdict(int)
        }