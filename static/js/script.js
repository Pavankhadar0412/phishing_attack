/**
 * Phishing Website Detector - Frontend JavaScript
 * Handles URL scanning, UI updates, and user interactions
 */

// DOM Elements
const scanForm = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const loadingSection = document.getElementById('loadingSection');
const resultSection = document.getElementById('resultSection');
const statusIndicator = document.getElementById('statusIndicator');
const statusIcon = document.getElementById('statusIcon');
const statusText = document.getElementById('statusText');
const confidenceBar = document.getElementById('confidenceBar');
const confidenceText = document.getElementById('confidenceText');
const riskLevel = document.getElementById('riskLevel');
const scannedUrl = document.getElementById('scannedUrl');
const phishingProb = document.getElementById('phishingProb');
const legitimateProb = document.getElementById('legitimateProb');
const virustotalSection = document.getElementById('virustotalSection');
const virustotalScore = document.getElementById('virustotalScore');

// Theme Toggle
const themeToggle = document.createElement('button');
themeToggle.className = 'theme-toggle';
themeToggle.innerHTML = '<i class="bi bi-moon"></i>';
themeToggle.setAttribute('aria-label', 'Toggle dark mode');
document.body.appendChild(themeToggle);

// Check for saved theme preference
const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

// Theme toggle event listener
themeToggle.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
});

function updateThemeIcon(theme) {
    const icon = themeToggle.querySelector('i');
    if (theme === 'dark') {
        icon.className = 'bi bi-sun';
    } else {
        icon.className = 'bi bi-moon';
    }
}

// Form submission handler
if (scanForm) {
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        
        if (!url) {
            showError('Please enter a URL to scan');
            return;
        }
        
        if (!isValidUrl(url)) {
            showError('Please enter a valid URL (e.g., https://example.com)');
            return;
        }
        
        await scanUrl(url);
    });
}

// URL validation
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// Show error message
function showError(message) {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-danger alert-dismissible fade show';
    alertDiv.innerHTML = `
        <i class="bi bi-exclamation-triangle"></i> ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert before the form
    scanForm.insertBefore(alertDiv, scanForm.firstChild);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Scan URL function
async function scanUrl(url) {
    // Show loading
    loadingSection.classList.remove('d-none');
    resultSection.classList.add('d-none');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Scanning...';
    
    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            displayResults(data);
        } else {
            showError(data.error || 'Scan failed. Please try again.');
            loadingSection.classList.add('d-none');
        }
    } catch (error) {
        showError('Network error. Please check your connection and try again.');
        console.error('Error:', error);
        loadingSection.classList.add('d-none');
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="bi bi-search"></i> Scan';
    }
}

// Display scan results
function displayResults(data) {
    // Hide loading, show results
    loadingSection.classList.add('d-none');
    resultSection.classList.remove('d-none');
    resultSection.classList.add('fade-in');
    
    // Update URL
    scannedUrl.textContent = data.url;
    
    // Update status indicator
    if (data.is_phishing) {
        statusIndicator.className = 'status-phishing text-center p-4 rounded mb-3';
        statusIcon.className = 'bi bi-exclamation-triangle display-1';
        statusText.textContent = 'PHISHING DETECTED';
    } else {
        statusIndicator.className = 'status-safe text-center p-4 rounded mb-3';
        statusIcon.className = 'bi bi-shield-check display-1';
        statusText.textContent = 'SAFE WEBSITE';
    }
    
    // Update confidence
    const confidence = data.confidence;
    confidenceBar.style.width = confidence + '%';
    confidenceBar.setAttribute('aria-valuenow', confidence);
    confidenceText.textContent = confidence.toFixed(2) + '% Confidence';
    
    // Update confidence bar color based on status
    if (data.is_phishing) {
        confidenceBar.className = 'progress-bar bg-danger';
    } else {
        confidenceBar.className = 'progress-bar bg-success';
    }
    
    // Update risk level
    riskLevel.textContent = data.risk_level;
    riskLevel.className = 'badge fs-6 badge-' + data.risk_level;
    
    // Update probabilities
    phishingProb.textContent = data.probability_phishing.toFixed(2) + '%';
    legitimateProb.textContent = data.probability_legitimate.toFixed(2) + '%';
    
    // Update VirusTotal if available
    if (data.virustotal && data.virustotal.score !== null) {
        virustotalSection.classList.remove('d-none');
        virustotalScore.textContent = `VirusTotal Score: ${data.virustotal.score}/100 (${data.virustotal.malicious}/${data.virustotal.total} engines detected as malicious)`;
    } else {
        virustotalSection.classList.add('d-none');
    }
    
    // Scroll to results
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Auto-format URL input
if (urlInput) {
    urlInput.addEventListener('blur', function() {
        let url = this.value.trim();
        
        if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
            this.value = url;
        }
    });
    
    // Allow Enter key to submit
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            scanForm.dispatchEvent(new Event('submit'));
        }
    });
}

// Copy URL to clipboard functionality
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success message
        const toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white bg-success border-0';
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="bi bi-check-circle"></i> URL copied to clipboard!
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        document.body.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        // Remove after toast is hidden
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    });
}

// Add copy button to scanned URL
if (scannedUrl) {
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-sm btn-outline-secondary ms-2';
    copyBtn.innerHTML = '<i class="bi bi-clipboard"></i>';
    copyBtn.setAttribute('title', 'Copy URL');
    copyBtn.addEventListener('click', () => {
        copyToClipboard(scannedUrl.textContent);
    });
    scannedUrl.parentNode.appendChild(copyBtn);
}

// Real-time URL validation feedback
if (urlInput) {
    urlInput.addEventListener('input', function() {
        const url = this.value.trim();
        const feedback = this.nextElementSibling;
        
        if (url && !isValidUrl(url)) {
            this.classList.add('is-invalid');
            if (feedback && feedback.classList.contains('form-text')) {
                feedback.classList.add('text-danger');
                feedback.textContent = 'Please enter a valid URL';
            }
        } else {
            this.classList.remove('is-invalid');
            if (feedback && feedback.classList.contains('form-text')) {
                feedback.classList.remove('text-danger');
                feedback.textContent = 'Enter the complete URL including http:// or https://';
            }
        }
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K to focus on URL input
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (urlInput) {
            urlInput.focus();
            urlInput.select();
        }
    }
    
    // Escape to clear results
    if (e.key === 'Escape') {
        if (resultSection && !resultSection.classList.contains('d-none')) {
            resultSection.classList.add('d-none');
            urlInput.value = '';
            urlInput.focus();
        }
    }
});

// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips if any
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize Bootstrap popovers if any
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Performance monitoring
if (window.performance) {
    window.addEventListener('load', function() {
        const perfData = window.performance.timing;
        const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
        console.log('Page load time:', pageLoadTime + 'ms');
    });
}

// Service Worker Registration (for PWA support)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        // Uncomment when service worker is implemented
        // navigator.serviceWorker.register('/sw.js').then(function(registration) {
        //     console.log('ServiceWorker registration successful');
        // }, function(err) {
        //     console.log('ServiceWorker registration failed: ', err);
        // });
    });
}

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        isValidUrl,
        scanUrl,
        displayResults,
        copyToClipboard
    };
}
