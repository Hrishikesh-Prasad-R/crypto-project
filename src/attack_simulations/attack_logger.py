"""
Attack Logging and Statistics System
Tracks all attack simulations and maintains detailed records

FILE: attack_logger.py
"""

import time
from collections import defaultdict
from datetime import datetime


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
        try:
            attack_record = {
                'timestamp': time.time(),
                'readable_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'attack_name': attack_data.get('attack_name', 'Unknown'),
                'attack_type': attack_data.get('attack_type', 'Unknown'),
                'success': attack_data.get('success', False),
                'protection': attack_data.get('protection', 'None'),
                'details': attack_data.get('details', {}),
                'technique': attack_data.get('technique', 'N/A'),
                'method': attack_data.get('method', 'N/A'),
                'lesson': attack_data.get('lesson', 'N/A')
            }
            
            self.attacks.append(attack_record)
            
            # Update statistics
            self.stats['total_attacks'] += 1
            
            if attack_record['success']:
                self.stats['successful_attacks'] += 1
            else:
                self.stats['failed_attacks'] += 1
            
            self.stats['attack_types'][attack_record['attack_type']] += 1
            
            if attack_record['protection'] and attack_record['protection'] != 'None':
                self.stats['protection_mechanisms'][attack_record['protection']] += 1
                
            return True
            
        except Exception as e:
            print(f"Error logging attack: {e}")
            return False
    
    def get_statistics(self):
        """Get current statistics with error handling"""
        try:
            return {
                'total_attacks': self.stats['total_attacks'],
                'successful_attacks': self.stats['successful_attacks'],
                'failed_attacks': self.stats['failed_attacks'],
                'unique_attacks': len(set(a['attack_name'] for a in self.attacks)) if self.attacks else 0,
                'attack_types': dict(self.stats['attack_types']),
                'protections': dict(self.stats['protection_mechanisms'])
            }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                'total_attacks': 0,
                'successful_attacks': 0,
                'failed_attacks': 0,
                'unique_attacks': 0,
                'attack_types': {},
                'protections': {}
            }
    
    def get_recent_attacks(self, n=5):
        """Get n most recent attacks"""
        try:
            return sorted(
                self.attacks,
                key=lambda x: x['timestamp'],
                reverse=True
            )[:n]
        except Exception as e:
            print(f"Error getting recent attacks: {e}")
            return []
    
    def get_attacks_by_type(self, attack_type):
        """Get all attacks of a specific type"""
        try:
            return [a for a in self.attacks if a.get('attack_type') == attack_type]
        except Exception as e:
            print(f"Error getting attacks by type: {e}")
            return []
    
    def get_success_rate(self):
        """Calculate overall success rate"""
        try:
            if self.stats['total_attacks'] == 0:
                return 0.0
            return (self.stats['successful_attacks'] / self.stats['total_attacks']) * 100
        except Exception as e:
            print(f"Error calculating success rate: {e}")
            return 0.0
    
    def get_attack_timeline(self):
        """Get attacks organized by time"""
        try:
            timeline = []
            for attack in sorted(self.attacks, key=lambda x: x['timestamp']):
                timeline.append({
                    'time': attack.get('readable_time', 'Unknown'),
                    'name': attack.get('attack_name', 'Unknown'),
                    'success': '✓' if attack.get('success') else '✗',
                    'protection': attack.get('protection', 'None')
                })
            return timeline
        except Exception as e:
            print(f"Error getting timeline: {e}")
            return []
    
    def export_summary(self):
        """Export a summary report"""
        try:
            summary = {
                'total_attacks': self.stats['total_attacks'],
                'successful': self.stats['successful_attacks'],
                'blocked': self.stats['failed_attacks'],
                'success_rate': self.get_success_rate(),
                'by_type': dict(self.stats['attack_types']),
                'protections_used': dict(self.stats['protection_mechanisms']),
                'recent_attacks': [
                    {
                        'name': a.get('attack_name'),
                        'time': a.get('readable_time'),
                        'success': a.get('success')
                    }
                    for a in self.get_recent_attacks(10)
                ]
            }
            return summary
        except Exception as e:
            print(f"Error exporting summary: {e}")
            return {}
    
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
    
    def __len__(self):
        """Return number of logged attacks"""
        return len(self.attacks)
    
    def __repr__(self):
        """String representation"""
        return f"AttackLogger(attacks={len(self.attacks)}, success_rate={self.get_success_rate():.1f}%)"