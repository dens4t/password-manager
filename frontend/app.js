const API_BASE = window.location.origin;

class Toast {
    static show(message, type = 'info', duration = 3000) {
        const container = document.getElementById('toast-container') || this.createContainer();
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-icon">${this.getIcon(type)}</div>
            <div class="toast-message">${message}</div>
        `;
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease-out reverse';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
    
    static createContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
        return container;
    }
    
    static getIcon(type) {
        const icons = {
            success: '✅',
            error: '❌',
            info: 'ℹ️'
        };
        return icons[type] || icons.info;
    }
}

class Auth {
    static async login(username, password) {
        try {
            const response = await fetch(`${API_BASE}/api/auth/login`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });
            
            const data = await response.json();
            
            if (response.ok) {
                localStorage.setItem('token', data.token);
                window.location.href = '/dashboard';
                return true;
            } else {
                Toast.show(data.error || 'Login failed', 'error');
                return false;
            }
        } catch (error) {
            Toast.show('Network error', 'error');
            return false;
        }
    }
    
    static async register(username, password) {
        try {
            const response = await fetch(`${API_BASE}/api/auth/register`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Toast.show('Registration successful', 'success');
                return true;
            } else {
                Toast.show(data.error || 'Registration failed', 'error');
                return false;
            }
        } catch (error) {
            Toast.show('Network error', 'error');
            return false;
        }
    }
    
    static isLoggedIn() {
        return !!localStorage.getItem('token');
    }
    
    static getToken() {
        return localStorage.getItem('token');
    }
    
    static logout() {
        localStorage.removeItem('token');
        window.location.href = '/';
    }
}

class PasswordManager {
    static async getAll() {
        try {
            const response = await fetch(`${API_BASE}/api/passwords`, {
                headers: {'Authorization': `Bearer ${Auth.getToken()}`}
            });
            
            if (!response.ok) throw new Error('Failed to fetch passwords');
            return await response.json();
        } catch (error) {
            Toast.show('Failed to load passwords', 'error');
            return [];
        }
    }
    
    static async create(password) {
        try {
            const response = await fetch(`${API_BASE}/api/passwords`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${Auth.getToken()}`
                },
                body: JSON.stringify(password)
            });
            
            if (!response.ok) throw new Error('Failed to create password');
            const data = await response.json();
            Toast.show('Password saved successfully', 'success');
            return data;
        } catch (error) {
            Toast.show('Failed to save password', 'error');
            return null;
        }
    }
    
    static async update(id, password) {
        try {
            const response = await fetch(`${API_BASE}/api/passwords/${id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${Auth.getToken()}`
                },
                body: JSON.stringify(password)
            });
            
            if (!response.ok) throw new Error('Failed to update password');
            Toast.show('Password updated successfully', 'success');
            return await response.json();
        } catch (error) {
            Toast.show('Failed to update password', 'error');
            return null;
        }
    }
    
    static async delete(id) {
        try {
            const response = await fetch(`${API_BASE}/api/passwords/${id}`, {
                method: 'DELETE',
                headers: {'Authorization': `Bearer ${Auth.getToken()}`}
            });
            
            if (!response.ok) throw new Error('Failed to delete password');
            Toast.show('Password deleted successfully', 'success');
            return true;
        } catch (error) {
            Toast.show('Failed to delete password', 'error');
            return false;
        }
    }
    
    static async generate(length = 16) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';
        
        // Ensure at least one of each type
        password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
        password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
        password += '0123456789'[Math.floor(Math.random() * 10)];
        password += '!@#$%^&*()_+-=[]{}|;:,.<>?'[Math.floor(Math.random() * 28)];
        
        // Fill the rest randomly
        for (let i = 4; i < length; i++) {
            password += chars[Math.floor(Math.random() * chars.length)];
        }
        
        // Shuffle the password
        return password.split('').sort(() => Math.random() - 0.5).join('');
    }
    
    static calculateStrength(password) {
        let score = 0;
        
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/[0-9]/.test(password)) score += 1;
        if (/[^a-zA-Z0-9]/.test(password)) score += 1;
        
        if (score >= 6) return 'strong';
        if (score >= 4) return 'medium';
        return 'weak';
    }
}

class ImportExport {
    static async exportPasswords(format = 'csv') {
        try {
            const passwords = await PasswordManager.getAll();
            
            if (format === 'csv') {
                return this.exportToCSV(passwords);
            } else if (format === 'json') {
                return this.exportToJSON(passwords);
            } else if (format === 'chrome') {
                return this.exportToChromeFormat(passwords);
            }
        } catch (error) {
            Toast.show('Export failed', 'error');
            return null;
        }
    }
    
    static exportToCSV(passwords) {
        const headers = ['title', 'username', 'password', 'url', 'notes'];
        const rows = passwords.map(p => [
            p.title,
            p.username,
            p.password,
            p.url || '',
            p.notes || ''
        ]);
        
        const csv = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${(cell || '').replace(/"/g, '""')}"`).join(','))
        ].join('\n');
        
        return csv;
    }
    
    static exportToJSON(passwords) {
        return JSON.stringify(passwords, null, 2);
    }
    
    static exportToChromeFormat(passwords) {
        const chromeFormat = {
            folders: [],
            items: passwords.map(p => ({
                name: p.title,
                url: p.url || '',
                username: p.username,
                password: p.password,
                notes: p.notes || '',
                date_created: new Date().toISOString()
            }))
        };
        
        return JSON.stringify(chromeFormat, null, 2);
    }
    
    static async importPasswords(file, format) {
        try {
            const text = await file.text();
            let passwords;
            
            if (format === 'csv') {
                passwords = this.parseCSV(text);
            } else if (format === 'json') {
                passwords = this.parseJSON(text);
            } else if (format === 'chrome') {
                passwords = this.parseChromeFormat(text);
            }
            
            // Import each password
            let successCount = 0;
            for (const password of passwords) {
                if (await PasswordManager.create(password)) {
                    successCount++;
                }
            }
            
            Toast.show(`Imported ${successCount} of ${passwords.length} passwords`, 'success');
            return successCount;
        } catch (error) {
            Toast.show('Import failed', 'error');
            return 0;
        }
    }
    
    static parseCSV(csvText) {
        const lines = csvText.split('\n');
        const headers = lines[0].split(',').map(h => h.replace(/"/g, ''));
        
        return lines.slice(1).map(line => {
            const values = this.parseCSVLine(line);
            const password = {};
            
            headers.forEach((header, index) => {
                if (values[index]) {
                    password[header] = values[index].replace(/""/g, '"');
                }
            });
            
            return password;
        }).filter(p => p.title && p.username && p.password);
    }
    
    static parseCSVLine(line) {
        const values = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            
            if (char === '"') {
                if (inQuotes && line[i + 1] === '"') {
                    current += '"';
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (char === ',' && !inQuotes) {
                values.push(current);
                current = '';
            } else {
                current += char;
            }
        }
        
        values.push(current);
        return values;
    }
    
    static parseJSON(jsonText) {
        const data = JSON.parse(jsonText);
        
        if (Array.isArray(data)) {
            return data;
        } else if (data.items) {
            // Chrome format
            return data.items.map(item => ({
                title: item.name,
                username: item.username,
                password: item.password,
                url: item.url,
                notes: item.notes
            }));
        }
        
        return [];
    }
    
    static parseChromeFormat(jsonText) {
        const data = JSON.parse(jsonText);
        
        if (data.items) {
            return data.items.map(item => ({
                title: item.name,
                username: item.username,
                password: item.password,
                url: item.url,
                notes: item.notes
            }));
        }
        
        return [];
    }
    
    static downloadFile(content, filename, type = 'text/plain') {
        const blob = new Blob([content], {type});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

// Utility functions
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(
        () => Toast.show('Copied to clipboard', 'success'),
        () => Toast.show('Failed to copy', 'error')
    );
}

function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        setTimeout(() => modal.style.opacity = '1', 10);
    }
}

function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.opacity = '0';
        setTimeout(() => modal.style.display = 'none', 300);
    }
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
}

// Render initial UI
function renderInitialUI() {
    const app = document.getElementById('app');
    if (!app) return;
    
    if (Auth.isLoggedIn()) {
        // Redirect to dashboard
        window.location.href = '/dashboard';
    } else {
        // Render login page
        app.innerHTML = `
            <div class="auth-container">
                <div class="auth-card">
                    <div class="logo">
                        <h1>🔐 SecurePass</h1>
                        <p>Your secure password manager</p>
                    </div>
                    
                    <div class="tabs">
                        <button class="tab-btn active" id="login-tab">Login</button>
                        <button class="tab-btn" id="register-tab">Register</button>
                    </div>
                    
                    <div id="login-form-container">
                        <form id="login-form" class="auth-form">
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" id="username" class="form-control" placeholder="Enter username" required>
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <div style="position: relative;">
                                    <input type="password" id="password" class="form-control" placeholder="Enter password" required>
                                    <button type="button" class="password-toggle" onclick="togglePasswordVisibility('password')">👁️</button>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                    </div>
                    
                    <div id="register-form-container" style="display: none;">
                        <form id="register-form" class="auth-form">
                            <div class="form-group">
                                <label for="reg-username">Username</label>
                                <input type="text" id="reg-username" class="form-control" placeholder="Choose username" required>
                            </div>
                            <div class="form-group">
                                <label for="reg-password">Password</label>
                                <div style="position: relative;">
                                    <input type="password" id="reg-password" class="form-control" placeholder="Create password" required>
                                    <button type="button" class="password-toggle" onclick="togglePasswordVisibility('reg-password')">👁️</button>
                                </div>
                                <div class="strength-meter">
                                    <div class="strength-fill strength-weak"></div>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="reg-confirm">Confirm Password</label>
                                <input type="password" id="reg-confirm" class="form-control" placeholder="Confirm password" required>
                            </div>
                            <button type="button" id="generate-btn" class="btn btn-outline" style="margin-bottom: 1rem;">Generate Strong Password</button>
                            <button type="submit" class="btn btn-secondary">Register</button>
                        </form>
                    </div>
                </div>
            </div>
        `;
        
        // Initialize tabs
        document.getElementById('login-tab').addEventListener('click', function() {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            document.getElementById('login-form-container').style.display = 'block';
            document.getElementById('register-form-container').style.display = 'none';
        });
        
        document.getElementById('register-tab').addEventListener('click', function() {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            document.getElementById('login-form-container').style.display = 'none';
            document.getElementById('register-form-container').style.display = 'block';
        });
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    renderInitialUI();
    
    // Add CSS for tabs
    const style = document.createElement('style');
    style.textContent = `
        .tabs {
            display: flex;
            margin-bottom: 2rem;
            border-bottom: 2px solid var(--gray-light);
        }
        .tab-btn {
            flex: 1;
            padding: 0.75rem;
            background: none;
            border: none;
            border-bottom: 3px solid transparent;
            font-size: 1rem;
            font-weight: 500;
            color: var(--gray);
            cursor: pointer;
            transition: all 0.2s;
        }
        .tab-btn.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
        }
        .tab-btn:hover:not(.active) {
            color: var(--dark);
        }
        .auth-form {
            margin-top: 1rem;
        }
        .password-toggle {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--gray);
            cursor: pointer;
            padding: 5px;
        }
        .password-toggle:hover {
            color: var(--primary);
        }
    `;
    document.head.appendChild(style);
    // Modal close handlers
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', function() {
            const modal = this.closest('.modal-overlay');
            if (modal) modal.style.display = 'none';
        });
    });
    
    // Close modal when clicking outside
    document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.addEventListener('click', function(e) {
            if (e.target === this) {
                this.style.display = 'none';
            }
        });
    });
    
    // Initialize auth forms
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = this.querySelector('#username').value;
            const password = this.querySelector('#password').value;
            await Auth.login(username, password);
        });
    }
    
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = this.querySelector('#reg-username').value;
            const password = this.querySelector('#reg-password').value;
            const confirm = this.querySelector('#reg-confirm').value;
            
            if (password !== confirm) {
                Toast.show('Passwords do not match', 'error');
                return;
            }
            
            await Auth.register(username, password);
        });
    }
    
    // Password generator
    const generateBtn = document.getElementById('generate-btn');
    if (generateBtn) {
        generateBtn.addEventListener('click', function() {
            const password = PasswordManager.generate(16);
            const passwordInput = document.getElementById('add-password');
            if (passwordInput) {
                passwordInput.value = password;
                updatePasswordStrength(password);
            }
        });
    }
    
    // Export functionality
    const exportBtn = document.getElementById('export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', async function() {
            const format = document.querySelector('.format-option.active')?.dataset.format || 'csv';
            const content = await ImportExport.exportPasswords(format);
            
            if (content) {
                ImportExport.downloadFile(content, `passwords_${new Date().toISOString().split('T')[0]}.${format}`, 
                    format === 'json' ? 'application/json' : 'text/csv');
            }
        });
    }
    
    // Import functionality
    const importFile = document.getElementById('import-file');
    if (importFile) {
        importFile.addEventListener('change', async function() {
            const file = this.files[0];
            if (!file) return;
            
            const format = document.querySelector('.format-option.active')?.dataset.format || 'csv';
            await ImportExport.importPasswords(file, format);
            
            // Reset file input
            this.value = '';
        });
    }
    
    // Format selector
    document.querySelectorAll('.format-option').forEach(option => {
        option.addEventListener('click', function() {
            document.querySelectorAll('.format-option').forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');
        });
    });
});

function updatePasswordStrength(password) {
    const strength = PasswordManager.calculateStrength(password);
    const meter = document.querySelector('.strength-fill');
    
    if (meter) {
        meter.className = 'strength-fill';
        meter.classList.add(`strength-${strength}`);
    }
}