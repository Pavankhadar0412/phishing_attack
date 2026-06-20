"""
URL Feature Extraction Module for Phishing Detection
Extracts 20+ features from URLs to detect phishing websites
"""

import re
import urllib.parse
from urllib.parse import urlparse
import math
from collections import Counter


class URLFeatureExtractor:
    """
    A class to extract various features from URLs for phishing detection.
    """
    
    def __init__(self):
        """Initialize the feature extractor with suspicious keywords and patterns."""
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'secure', 'update',
            'banking', 'confirm', 'wallet', 'password', 'credential',
            'authenticate', 'validation', 'security', 'admin', 'support',
            'service', 'billing', 'payment', 'transaction', 'deposit',
            'withdraw', 'transfer', 'crypto', 'bitcoin', 'ethereum'
        ]
        
        self.shortening_services = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'lnkd.in', 'fb.me',
            'goo.gl', 'tiny.cc', 'short.link', 'tr.im', 'snip.ly', 'linktr.ee'
        ]
        
        self.tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
                    '.biz', '.info', '.io', '.co', '.us', '.uk', '.ca', '.au',
                    '.de', '.fr', '.jp', '.cn', '.in', '.br', '.ru', '.es']
    
    def extract_features(self, url):
        """
        Extract all features from a given URL.
        
        Args:
            url (str): The URL to extract features from
            
        Returns:
            dict: Dictionary containing all extracted features
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            # Basic URL features
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['query_length'] = len(query)
            
            # Character counts
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_question_marks'] = url.count('?')
            features['num_equals'] = url.count('=')
            features['num_ampersands'] = url.count('&')
            features['num_percent'] = url.count('%')
            
            # Digit and letter counts
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_letters'] = sum(c.isalpha() for c in url)
            features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', url))
            
            # Protocol features
            features['has_https'] = 1 if url.startswith('https') else 0
            features['has_http'] = 1 if url.startswith('http') else 0
            
            # Special symbols
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_ip_address'] = 1 if self._has_ip_address(domain) else 0
            features['has_port'] = 1 if ':' in domain else 0
            
            # Domain features
            features['num_subdomains'] = self._count_subdomains(domain)
            features['has_cname'] = 1 if 'www.' in domain else 0
            features['domain_age'] = self._estimate_domain_age(domain)
            
            # Suspicious keywords
            features['num_suspicious_keywords'] = self._count_suspicious_keywords(url)
            features['has_suspicious_keywords'] = 1 if features['num_suspicious_keywords'] > 0 else 0
            
            # URL shortening
            features['is_shortened'] = 1 if self._is_shortened_url(domain) else 0
            
            # TLD features
            features['tld_length'] = self._get_tld_length(domain)
            features['has_suspicious_tld'] = 1 if self._has_suspicious_tld(domain) else 0
            
            # Path features
            features['path_depth'] = self._count_path_depth(path)
            features['has_executable'] = 1 if any(ext in path.lower() for ext in ['.exe', '.php', '.asp', '.jsp']) else 0
            
            # Query features
            features['num_params'] = len(query.split('&')) if query else 0
            features['has_sensitive_params'] = 1 if self._has_sensitive_params(query) else 0
            
            # Entropy and complexity
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(domain)
            features['has_high_entropy'] = 1 if features['url_entropy'] > 4.0 else 0
            
            # Brand and homograph features
            features['has_brand_name'] = 1 if self._has_brand_name(domain) else 0
            features['has_homograph'] = 1 if self._has_homograph_chars(domain) else 0
            
            # Security indicators
            features['has_ssl_indicator'] = 1 if any(word in url.lower() for word in ['secure', 'ssl', 'lock']) else 0
            features['has_redirect'] = 1 if any(word in url.lower() for word in ['redirect', 'forward']) else 0
            
            # Ratio features
            features['digit_ratio'] = features['num_digits'] / features['url_length'] if features['url_length'] > 0 else 0
            features['special_char_ratio'] = features['num_special_chars'] / features['url_length'] if features['url_length'] > 0 else 0
            
        except Exception as e:
            print(f"Error extracting features from URL {url}: {e}")
            # Return default values if extraction fails
            features = self._get_default_features()
        
        return features
    
    def _has_ip_address(self, domain):
        """Check if the domain contains an IP address."""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, domain))
    
    def _count_subdomains(self, domain):
        """Count the number of subdomains in the domain."""
        parts = domain.split('.')
        # Remove www if present and count remaining parts minus TLD
        if parts[0] == 'www':
            parts = parts[1:]
        return max(0, len(parts) - 2)
    
    def _estimate_domain_age(self, domain):
        """
        Estimate domain age based on length and complexity.
        This is a heuristic since we can't actually check domain age without external API.
        """
        # Shorter, simpler domains are typically older
        length_score = max(0, 20 - len(domain))
        complexity_score = 10 - domain.count('-') - domain.count('.')
        return max(0, min(10, length_score + complexity_score))
    
    def _count_suspicious_keywords(self, url):
        """Count the number of suspicious keywords in the URL."""
        url_lower = url.lower()
        count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                count += 1
        return count
    
    def _is_shortened_url(self, domain):
        """Check if the URL is from a known URL shortening service."""
        domain_lower = domain.lower()
        for service in self.shortening_services:
            if service in domain_lower:
                return True
        return False
    
    def _get_tld_length(self, domain):
        """Get the length of the top-level domain."""
        parts = domain.split('.')
        if len(parts) >= 2:
            return len(parts[-1])
        return 0
    
    def _has_suspicious_tld(self, domain):
        """Check if the domain has a suspicious TLD."""
        suspicious_tlds = ['.xyz', '.top', '.zip', '.tk', '.ml', '.ga', '.cf', '.gq']
        domain_lower = domain.lower()
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                return True
        return False
    
    def _count_path_depth(self, path):
        """Count the depth of the path (number of directories)."""
        return path.count('/')
    
    def _has_sensitive_params(self, query):
        """Check if query parameters contain sensitive information."""
        sensitive_params = ['password', 'pass', 'pwd', 'token', 'key', 'secret', 
                           'auth', 'login', 'user', 'username', 'email']
        query_lower = query.lower()
        for param in sensitive_params:
            if param in query_lower:
                return True
        return False
    
    def _calculate_entropy(self, string):
        """
        Calculate the Shannon entropy of a string.
        Higher entropy indicates more random/complex strings.
        """
        if not string:
            return 0.0
        
        # Count character frequencies
        counter = Counter(string)
        length = len(string)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _has_brand_name(self, domain):
        """Check if domain contains common brand names (potential typosquatting)."""
        brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
                 'paypal', 'ebay', 'twitter', 'instagram', 'linkedin', 'yahoo',
                 'bank', 'chase', 'wells', 'citi', 'american', 'express']
        domain_lower = domain.lower()
        for brand in brands:
            if brand in domain_lower:
                return True
        return False
    
    def _has_homograph_chars(self, domain):
        """Check for homograph characters (look-alike characters used in phishing)."""
        # Common homograph characters
        homograph_chars = ['а', 'с', 'е', 'о', 'р', 'х', 'у', 'і', 'ј', 'ɡ']
        for char in homograph_chars:
            if char in domain:
                return True
        return False
    
    def _get_default_features(self):
        """Return default feature values when extraction fails."""
        return {
            'url_length': 0,
            'domain_length': 0,
            'path_length': 0,
            'query_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_slashes': 0,
            'num_question_marks': 0,
            'num_equals': 0,
            'num_ampersands': 0,
            'num_percent': 0,
            'num_digits': 0,
            'num_letters': 0,
            'num_special_chars': 0,
            'has_https': 0,
            'has_http': 0,
            'has_at_symbol': 0,
            'has_ip_address': 0,
            'has_port': 0,
            'num_subdomains': 0,
            'has_cname': 0,
            'domain_age': 0,
            'num_suspicious_keywords': 0,
            'has_suspicious_keywords': 0,
            'is_shortened': 0,
            'tld_length': 0,
            'has_suspicious_tld': 0,
            'path_depth': 0,
            'has_executable': 0,
            'num_params': 0,
            'has_sensitive_params': 0,
            'url_entropy': 0.0,
            'domain_entropy': 0.0,
            'has_high_entropy': 0,
            'has_brand_name': 0,
            'has_homograph': 0,
            'has_ssl_indicator': 0,
            'has_redirect': 0,
            'digit_ratio': 0.0,
            'special_char_ratio': 0.0
        }
    
    def get_feature_names(self):
        """Return the list of all feature names."""
        return list(self._get_default_features().keys())


# Singleton instance for easy import
extractor = URLFeatureExtractor()


def extract_url_features(url):
    """
    Convenience function to extract features from a URL.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary of extracted features
    """
    return extractor.extract_features(url)


if __name__ == "__main__":
    # Test the feature extractor
    test_urls = [
        "https://www.google.com",
        "http://phishing-site.com/login",
        "https://secure-banking-update.com/verify-account",
        "http://192.168.1.1/admin",
        "https://bit.ly/malicious-link"
    ]
    
    print("Testing URL Feature Extraction")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_url_features(url)
        for key, value in features.items():
            print(f"  {key}: {value}")
