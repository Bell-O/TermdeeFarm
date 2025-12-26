// ==================== Termdee Farm - Enhanced JavaScript ====================
// Modern, Interactive, Accessible

// ==================== CONFIGURATION ====================
const CONFIG = {
    toastDuration: 5000,
    animationDuration: 300,
    debounceDelay: 300,
    scrollThreshold: 50,
  }
  
  // ==================== UTILITY FUNCTIONS ====================
  
  // Debounce function
  function debounce(func, wait) {
    let timeout
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout)
        func(...args)
      }
      clearTimeout(timeout)
      timeout = setTimeout(later, wait)
    }
  }
  
  // Throttle function
  function throttle(func, limit) {
    let inThrottle
    return function (...args) {
      if (!inThrottle) {
        func.apply(this, args)
        inThrottle = true
        setTimeout(() => (inThrottle = false), limit)
      }
    }
  }
  
  // Format numbers with commas
  function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",")
  }
  
  // Format currency
  function formatCurrency(amount, currency = "฿") {
    return `${currency}${formatNumber(Number.parseFloat(amount).toFixed(2))}`
  }
  
  // Format date
  function formatDate(date, locale = "th-TH") {
    return new Date(date).toLocaleDateString(locale, {
      year: "numeric",
      month: "short",
      day: "numeric",
    })
  }
  
  // Format time ago
  function timeAgo(date) {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000)
    const intervals = {
      ปี: 31536000,
      เดือน: 2592000,
      สัปดาห์: 604800,
      วัน: 86400,
      ชั่วโมง: 3600,
      นาที: 60,
    }
  
    for (const [unit, secondsInUnit] of Object.entries(intervals)) {
      const interval = Math.floor(seconds / secondsInUnit)
      if (interval >= 1) {
        return `${interval} ${unit}ที่แล้ว`
      }
    }
    return "เมื่อสักครู่"
  }
  
  // ==================== TOAST NOTIFICATION SYSTEM ====================
  let toastContainer = null
  
  function initToastContainer() {
    if (!toastContainer) {
      toastContainer = document.createElement("div")
      toastContainer.id = "toast-container"
      toastContainer.setAttribute("role", "alert")
      toastContainer.setAttribute("aria-live", "polite")
      Object.assign(toastContainer.style, {
        position: "fixed",
        top: "calc(var(--navbar-height, 70px) + 16px)",
        right: "16px",
        zIndex: "var(--z-toast, 600)",
        display: "flex",
        flexDirection: "column",
        gap: "12px",
        maxWidth: "420px",
        width: "calc(100% - 32px)",
        pointerEvents: "none",
      })
      document.body.appendChild(toastContainer)
    }
    return toastContainer
  }
  
  function showToast(message, type = "info", duration = CONFIG.toastDuration) {
    initToastContainer()
  
    const toast = document.createElement("div")
    toast.className = `toast toast-${type}`
    toast.style.pointerEvents = "auto"
  
    const colors = {
      success: {
        bg: "var(--success-light, #d1fae5)",
        border: "var(--success-color, #10b981)",
        text: "#065f46",
      },
      error: {
        bg: "var(--danger-light, #fee2e2)",
        border: "var(--danger-color, #ef4444)",
        text: "#991b1b",
      },
      warning: {
        bg: "var(--warning-light, #fef3c7)",
        border: "var(--warning-color, #f59e0b)",
        text: "#92400e",
      },
      info: {
        bg: "var(--primary-lighter, #dbeafe)",
        border: "var(--primary-color, #2563eb)",
        text: "#1e40af",
      },
    }
  
    const icons = {
      success: "fa-check-circle",
      error: "fa-exclamation-circle",
      warning: "fa-exclamation-triangle",
      info: "fa-info-circle",
    }
  
    const color = colors[type] || colors.info
  
    Object.assign(toast.style, {
      background: color.bg,
      borderLeft: `4px solid ${color.border}`,
      color: color.text,
      padding: "1rem 1.25rem",
      borderRadius: "var(--radius-lg, 12px)",
      boxShadow: "var(--shadow-lg)",
      display: "flex",
      alignItems: "flex-start",
      gap: "0.75rem",
      animation: "slideInRight 0.3s ease-out",
      transform: "translateX(0)",
    })
  
    toast.innerHTML = `
      <i class="fas ${icons[type] || icons.info}" style="margin-top: 2px; flex-shrink: 0;"></i>
      <div style="flex: 1; font-size: 0.9375rem; line-height: 1.5;">${message}</div>
      <button onclick="this.closest('.toast').remove()" style="
        background: none;
        border: none;
        font-size: 1.25rem;
        cursor: pointer;
        color: inherit;
        opacity: 0.6;
        padding: 0;
        line-height: 1;
        transition: opacity 0.2s;
      " onmouseover="this.style.opacity='1'" onmouseout="this.style.opacity='0.6'">&times;</button>
    `
  
    toastContainer.appendChild(toast)
  
    // Auto remove
    if (duration > 0) {
      setTimeout(() => removeToast(toast), duration)
    }
  
    return toast
  }
  
  function removeToast(toast) {
    if (!toast || !toast.parentNode) return
  
    toast.style.animation = "slideOutRight 0.3s ease-out forwards"
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast)
      }
    }, 300)
  }
  
  // Alias for backward compatibility
  function showAlert(message, type = "info") {
    showToast(message, type)
  }
  
  // ==================== CONFIRMATION MODAL ====================
  function showConfirmModal(message, onConfirm, onCancel = null, options = {}) {
    const { title = "ยืนยันการดำเนินการ", confirmText = "ยืนยัน", cancelText = "ยกเลิก", confirmClass = "btn-danger" } = options
  
    // Remove existing modal
    const existingModal = document.getElementById("confirm-modal")
    if (existingModal) existingModal.remove()
  
    const modal = document.createElement("div")
    modal.id = "confirm-modal"
    modal.className = "modal-backdrop"
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.5);
      backdrop-filter: blur(4px);
      z-index: var(--z-modal-backdrop, 400);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
      animation: fadeIn 0.2s ease;
    `
  
    modal.innerHTML = `
      <div class="modal modal-sm" style="
        position: relative;
        transform: none;
        top: auto;
        left: auto;
        opacity: 1;
        visibility: visible;
        animation: scaleIn 0.2s ease;
        width: 100%;
        max-width: 400px;
      ">
        <div class="modal-header">
          <h3 class="modal-title">${title}</h3>
          <button class="modal-close" data-action="cancel">&times;</button>
        </div>
        <div class="modal-body">
          <p style="margin: 0; white-space: pre-line; line-height: 1.6;">${message}</p>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" data-action="cancel">${cancelText}</button>
          <button class="btn ${confirmClass}" data-action="confirm">${confirmText}</button>
        </div>
      </div>
    `
  
    document.body.appendChild(modal)
    document.body.style.overflow = "hidden"
  
    // Focus trap
    const confirmBtn = modal.querySelector('[data-action="confirm"]')
    confirmBtn.focus()
  
    const closeModal = (confirmed) => {
      document.body.style.overflow = ""
      modal.style.animation = "fadeOut 0.2s ease forwards"
      setTimeout(() => modal.remove(), 200)
      if (confirmed && onConfirm) onConfirm()
      if (!confirmed && onCancel) onCancel()
    }
  
    // Event handlers
    modal.addEventListener("click", (e) => {
      if (e.target === modal || e.target.dataset.action === "cancel") {
        closeModal(false)
      } else if (e.target.dataset.action === "confirm") {
        closeModal(true)
      }
    })
  
    // Escape key
    const escHandler = (e) => {
      if (e.key === "Escape") {
        closeModal(false)
        document.removeEventListener("keydown", escHandler)
      }
    }
    document.addEventListener("keydown", escHandler)
  
    return modal
  }
  
  // ==================== LOADING STATE ====================
  function showLoading(element, text = "กำลังโหลด...") {
    if (typeof element === "string") {
      element = document.querySelector(element)
    }
    if (!element) return
  
    element.disabled = true
    element.dataset.originalHtml = element.innerHTML
    element.innerHTML = `<span class="spinner spinner-sm" style="margin-right: 0.5rem;"></span>${text}`
  }
  
  function hideLoading(element) {
    if (typeof element === "string") {
      element = document.querySelector(element)
    }
    if (!element) return
  
    element.disabled = false
    if (element.dataset.originalHtml) {
      element.innerHTML = element.dataset.originalHtml
      delete element.dataset.originalHtml
    }
  }
  
  // Full page loading
  function showPageLoading() {
    let overlay = document.getElementById("page-loading")
    if (!overlay) {
      overlay = document.createElement("div")
      overlay.id = "page-loading"
      overlay.className = "loading-overlay"
      overlay.innerHTML = `
        <div style="text-align: center;">
          <div class="spinner spinner-lg" style="margin: 0 auto 1rem;"></div>
          <p style="color: var(--text-secondary);">กำลังโหลด...</p>
        </div>
      `
      document.body.appendChild(overlay)
    }
    requestAnimationFrame(() => overlay.classList.add("active"))
  }
  
  function hidePageLoading() {
    const overlay = document.getElementById("page-loading")
    if (overlay) {
      overlay.classList.remove("active")
      setTimeout(() => overlay.remove(), 300)
    }
  }
  
  // ==================== NAVBAR SCROLL EFFECT ====================
  function initNavbarScroll() {
    const navbar = document.querySelector(".navbar")
    if (!navbar) return
  
    const handleScroll = throttle(() => {
      if (window.scrollY > CONFIG.scrollThreshold) {
        navbar.classList.add("scrolled")
      } else {
        navbar.classList.remove("scrolled")
      }
    }, 100)
  
    window.addEventListener("scroll", handleScroll, { passive: true })
  }
  
  // ==================== MOBILE MENU ====================
  function initMobileMenu() {
    const toggle = document.querySelector(".mobile-menu-toggle")
    const menu = document.querySelector(".nav-menu")
  
    if (!toggle || !menu) return
  
    toggle.addEventListener("click", (e) => {
      e.stopPropagation()
      const isActive = menu.classList.toggle("active")
      menu.classList.toggle("is-active", isActive)
      toggle.setAttribute("aria-expanded", isActive)
  
      // Animate icon
      const icon = toggle.querySelector("i")
      if (icon) {
        icon.className = isActive ? "fas fa-times" : "fas fa-bars"
      }
    })
  
    // Close menu when clicking outside
    document.addEventListener("click", (e) => {
      if (!menu.contains(e.target) && !toggle.contains(e.target)) {
        menu.classList.remove("active", "is-active")
        toggle.setAttribute("aria-expanded", "false")
        const icon = toggle.querySelector("i")
        if (icon) icon.className = "fas fa-bars"
      }
    })
  
    // Close menu on escape
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && menu.classList.contains("active")) {
        menu.classList.remove("active", "is-active")
        toggle.setAttribute("aria-expanded", "false")
        toggle.focus()
      }
    })
  }
  
  // ==================== DROPDOWN ====================
  function initDropdowns() {
    document.querySelectorAll(".dropdown").forEach((dropdown) => {
      const toggle = dropdown.querySelector(".dropdown-toggle")
      const menu = dropdown.querySelector(".dropdown-menu")
  
      if (!toggle || !menu) return
  
      toggle.addEventListener("click", (e) => {
        e.preventDefault()
        e.stopPropagation()
  
        // Close other dropdowns
        document.querySelectorAll(".dropdown-menu.active").forEach((m) => {
          if (m !== menu) m.classList.remove("active")
        })
  
        menu.classList.toggle("active")
      })
    })
  
    // Close dropdowns when clicking outside
    document.addEventListener("click", () => {
      document.querySelectorAll(".dropdown-menu.active").forEach((menu) => {
        menu.classList.remove("active")
      })
    })
  }
  
  // ==================== TABS ====================
  function initTabs() {
    document.querySelectorAll(".tabs").forEach((tabContainer) => {
      const tabs = tabContainer.querySelectorAll(".tab")
  
      tabs.forEach((tab) => {
        tab.addEventListener("click", () => {
          const target = tab.dataset.tab
          if (!target) return
  
          // Update active tab
          tabs.forEach((t) => t.classList.remove("active"))
          tab.classList.add("active")
  
          // Update content
          const parent = tabContainer.closest(".card") || document
          parent.querySelectorAll(".tab-content").forEach((content) => {
            content.classList.remove("active")
            if (content.id === target) {
              content.classList.add("active")
            }
          })
        })
      })
    })
  }
  
  // ==================== TOOLTIPS ====================
  function initTooltips() {
    // Tooltips are handled via CSS with data-tooltip attribute
    // This function can be used for dynamic tooltips if needed
  }
  
  // ==================== FORM VALIDATION ====================
  function initFormValidation() {
    document.querySelectorAll("form[data-validate]").forEach((form) => {
      form.addEventListener("submit", (e) => {
        let isValid = true
  
        // Check required fields
        form.querySelectorAll("[required]").forEach((field) => {
          if (!field.value.trim()) {
            isValid = false
            showFieldError(field, "กรุณากรอกข้อมูลนี้")
          } else {
            clearFieldError(field)
          }
        })
  
        // Check email fields
        form.querySelectorAll('input[type="email"]').forEach((field) => {
          if (field.value && !isValidEmail(field.value)) {
            isValid = false
            showFieldError(field, "รูปแบบอีเมลไม่ถูกต้อง")
          }
        })
  
        if (!isValid) {
          e.preventDefault()
          showToast("กรุณาตรวจสอบข้อมูลที่กรอก", "error")
        }
      })
    })
  }
  
  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  }
  
  function showFieldError(field, message) {
    clearFieldError(field)
  
    field.classList.add("is-invalid")
    field.style.borderColor = "var(--danger-color)"
  
    const error = document.createElement("div")
    error.className = "field-error"
    error.style.cssText = `
      color: var(--danger-color);
      font-size: 0.8125rem;
      margin-top: 0.25rem;
    `
    error.textContent = message
  
    field.parentNode.appendChild(error)
  }
  
  function clearFieldError(field) {
    field.classList.remove("is-invalid")
    field.style.borderColor = ""
  
    const error = field.parentNode.querySelector(".field-error")
    if (error) error.remove()
  }
  
  // ==================== PASSWORD STRENGTH ====================
  function checkPasswordStrength(password) {
    let strength = 0
    const feedback = []
  
    if (password.length >= 8) strength++
    else feedback.push("รหัสผ่านควรมีอย่างน้อย 8 ตัวอักษร")
  
    if (/[a-z]/.test(password)) strength++
    else feedback.push("ควรมีตัวอักษรพิมพ์เล็ก")
  
    if (/[A-Z]/.test(password)) strength++
    else feedback.push("ควรมีตัวอักษรพิมพ์ใหญ่")
  
    if (/[0-9]/.test(password)) strength++
    else feedback.push("ควรมีตัวเลข")
  
    if (/[^a-zA-Z0-9]/.test(password)) strength++
    else feedback.push("ควรมีอักขระพิเศษ")
  
    const levels = ["ต่ำมาก", "ต่ำ", "ปานกลาง", "ดี", "ดีมาก"]
    const colors = ["#ef4444", "#f97316", "#f59e0b", "#10b981", "#059669"]
  
    return {
      strength,
      level: levels[strength - 1] || levels[0],
      color: colors[strength - 1] || colors[0],
      feedback,
      percentage: (strength / 5) * 100,
    }
  }
  
  function initPasswordStrength() {
    document.querySelectorAll('input[type="password"][data-strength]').forEach((input) => {
      const meter = document.createElement("div")
      meter.className = "password-strength-meter"
      meter.style.cssText = `
        height: 4px;
        background: var(--bg-tertiary);
        border-radius: var(--radius-full);
        margin-top: 0.5rem;
        overflow: hidden;
      `
  
      const bar = document.createElement("div")
      bar.style.cssText = `
        height: 100%;
        width: 0;
        transition: all 0.3s ease;
        border-radius: var(--radius-full);
      `
      meter.appendChild(bar)
  
      const label = document.createElement("div")
      label.style.cssText = `
        font-size: 0.75rem;
        margin-top: 0.25rem;
        color: var(--text-muted);
      `
  
      input.parentNode.appendChild(meter)
      input.parentNode.appendChild(label)
  
      input.addEventListener("input", () => {
        const result = checkPasswordStrength(input.value)
        bar.style.width = `${result.percentage}%`
        bar.style.background = result.color
        label.textContent = input.value ? `ความแข็งแรง: ${result.level}` : ""
        label.style.color = result.color
      })
    })
  }
  
  // ==================== SEARCH FUNCTIONALITY ====================
  function initSearch() {
    document.querySelectorAll("input[data-search-table]").forEach((input) => {
      const tableId = input.dataset.searchTable
      const table = document.getElementById(tableId)
  
      if (!table) return
  
      const searchHandler = debounce(() => {
        const searchTerm = input.value.toLowerCase().trim()
        const rows = table.querySelectorAll("tbody tr")
  
        rows.forEach((row) => {
          const text = row.textContent.toLowerCase()
          const match = text.includes(searchTerm)
          row.style.display = match ? "" : "none"
        })
  
        // Show/hide empty state
        const visibleRows = table.querySelectorAll('tbody tr:not([style*="display: none"])')
        let emptyState = table.parentNode.querySelector(".table-empty-search")
  
        if (visibleRows.length === 0 && searchTerm) {
          if (!emptyState) {
            emptyState = document.createElement("div")
            emptyState.className = "table-empty-search empty-state"
            emptyState.innerHTML = `
              <div class="empty-state-icon"><i class="fas fa-search"></i></div>
              <p class="empty-state-title">ไม่พบข้อมูล</p>
              <p class="empty-state-text">ไม่พบผลลัพธ์สำหรับ "${searchTerm}"</p>
            `
            table.parentNode.appendChild(emptyState)
          }
        } else if (emptyState) {
          emptyState.remove()
        }
      }, CONFIG.debounceDelay)
  
      input.addEventListener("input", searchHandler)
    })
  }
  
  // ==================== COPY TO CLIPBOARD ====================
  async function copyToClipboard(text, successMessage = "คัดลอกแล้ว!") {
    try {
      await navigator.clipboard.writeText(text)
      showToast(successMessage, "success", 2000)
      return true
    } catch (err) {
      // Fallback for older browsers
      const textArea = document.createElement("textarea")
      textArea.value = text
      textArea.style.cssText = "position:fixed;left:-9999px"
      document.body.appendChild(textArea)
      textArea.select()
  
      try {
        document.execCommand("copy")
        showToast(successMessage, "success", 2000)
        return true
      } catch (e) {
        showToast("ไม่สามารถคัดลอกได้", "error")
        return false
      } finally {
        document.body.removeChild(textArea)
      }
    }
  }
  
  function initCopyButtons() {
    document.querySelectorAll("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const text = btn.dataset.copy
        copyToClipboard(text)
      })
    })
  }
  
  // ==================== ANIMATED COUNTERS ====================
  function animateCounter(element, target, duration = 1000) {
    const start = 0
    const startTime = performance.now()
  
    function update(currentTime) {
      const elapsed = currentTime - startTime
      const progress = Math.min(elapsed / duration, 1)
  
      // Easing function
      const easeOut = 1 - Math.pow(1 - progress, 3)
      const current = Math.floor(start + (target - start) * easeOut)
  
      element.textContent = formatNumber(current)
  
      if (progress < 1) {
        requestAnimationFrame(update)
      }
    }
  
    requestAnimationFrame(update)
  }
  
  function initCounters() {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const target = Number.parseInt(entry.target.dataset.count, 10)
            animateCounter(entry.target, target)
            observer.unobserve(entry.target)
          }
        })
      },
      { threshold: 0.5 },
    )
  
    document.querySelectorAll("[data-count]").forEach((el) => {
      observer.observe(el)
    })
  }
  
  // ==================== PROGRESS BAR ANIMATION ====================
  function initProgressBars() {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const bar = entry.target
            const targetWidth = bar.dataset.progress || bar.style.width
            bar.style.width = "0"
  
            requestAnimationFrame(() => {
              bar.style.width = targetWidth
            })
  
            observer.unobserve(bar)
          }
        })
      },
      { threshold: 0.5 },
    )
  
    document.querySelectorAll(".progress-bar").forEach((bar) => {
      observer.observe(bar)
    })
  }
  
  // ==================== BULK ACTIONS ====================
  function initBulkActions() {
    const selectAll = document.getElementById("select-all")
    if (!selectAll) return
  
    const checkboxes = document.querySelectorAll('input[name="selected_items"]')
    const bulkActions = document.querySelector(".bulk-actions")
  
    selectAll.addEventListener("change", () => {
      checkboxes.forEach((cb) => (cb.checked = selectAll.checked))
      updateBulkActionsVisibility()
    })
  
    checkboxes.forEach((cb) => {
      cb.addEventListener("change", () => {
        selectAll.checked = [...checkboxes].every((c) => c.checked)
        selectAll.indeterminate = [...checkboxes].some((c) => c.checked) && ![...checkboxes].every((c) => c.checked)
        updateBulkActionsVisibility()
      })
    })
  
    function updateBulkActionsVisibility() {
      const hasSelected = [...checkboxes].some((c) => c.checked)
      if (bulkActions) {
        bulkActions.style.display = hasSelected ? "flex" : "none"
      }
    }
  }
  
  // ==================== FLASH MESSAGES ====================
  function initFlashMessages() {
    const flashMessages = document.querySelectorAll(".flash-messages .alert")
  
    flashMessages.forEach((msg) => {
      const text = msg.textContent.trim()
      const category = msg.className.includes("error")
        ? "error"
        : msg.className.includes("success")
          ? "success"
          : msg.className.includes("warning")
            ? "warning"
            : "info"
  
      showToast(text, category)
      msg.remove()
    })
  }
  
  // ==================== SMOOTH SCROLL ====================
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
      anchor.addEventListener("click", (e) => {
        const href = anchor.getAttribute("href")
        if (href === "#") return
  
        const target = document.querySelector(href)
        if (target) {
          e.preventDefault()
          target.scrollIntoView({
            behavior: "smooth",
            block: "start",
          })
        }
      })
    })
  }
  
  // ==================== AUTO REFRESH ====================
  function initAutoRefresh() {
    const refreshElements = document.querySelectorAll("[data-auto-refresh]")
  
    refreshElements.forEach((element) => {
      const interval = Number.parseInt(element.dataset.autoRefresh, 10) * 1000
      const url = element.dataset.refreshUrl || window.location.href
  
      setInterval(async () => {
        try {
          const response = await fetch(url, {
            headers: { "X-Requested-With": "XMLHttpRequest" },
          })
  
          if (response.ok) {
            const html = await response.text()
            const parser = new DOMParser()
            const doc = parser.parseFromString(html, "text/html")
            const newContent = doc.querySelector(`#${element.id}`)
  
            if (newContent) {
              element.innerHTML = newContent.innerHTML
            }
          }
        } catch (error) {
          console.error("Auto-refresh failed:", error)
        }
      }, interval)
    })
  }
  
  // ==================== KEYBOARD SHORTCUTS ====================
  function initKeyboardShortcuts() {
    document.addEventListener("keydown", (e) => {
      // Ctrl/Cmd + K for search focus
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault()
        const searchInput = document.querySelector('input[type="search"], input[data-search-table]')
        if (searchInput) searchInput.focus()
      }
  
      // Escape to close modals/dropdowns
      if (e.key === "Escape") {
        document.querySelectorAll(".dropdown-menu.active").forEach((m) => m.classList.remove("active"))
      }
    })
  }
  
  // ==================== INTERSECTION ANIMATIONS ====================
  function initScrollAnimations() {
    const animatedElements = document.querySelectorAll("[data-animate]")
  
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const animation = entry.target.dataset.animate || "fade-in-up"
            entry.target.classList.add(`animate-${animation}`)
            observer.unobserve(entry.target)
          }
        })
      },
      {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px",
      },
    )
  
    animatedElements.forEach((el) => observer.observe(el))
  }
  
  // ==================== INITIALIZE ALL ====================
  document.addEventListener("DOMContentLoaded", () => {
    // Core functionality
    initNavbarScroll()
    initMobileMenu()
    initDropdowns()
    initTabs()
    initTooltips()
  
    // Forms
    initFormValidation()
    initPasswordStrength()
    initSearch()
    initBulkActions()
  
    // UI enhancements
    initCopyButtons()
    initCounters()
    initProgressBars()
    initScrollAnimations()
    initSmoothScroll()
  
    // Notifications
    initFlashMessages()
  
    // Shortcuts
    initKeyboardShortcuts()
  
    // Optional: Auto refresh
    initAutoRefresh()
  
    // Add toast animation styles
    if (!document.getElementById("dynamic-styles")) {
      const style = document.createElement("style")
      style.id = "dynamic-styles"
      style.textContent = `
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOutRight {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100%); opacity: 0; }
        }
        @keyframes fadeOut {
          from { opacity: 1; }
          to { opacity: 0; }
        }
      `
      document.head.appendChild(style)
    }
  
    console.log("🌾 Termdee Farm UI initialized")
  })
  
  // Export for global access
  window.TerdeeFarm = {
    showToast,
    showAlert,
    showConfirmModal,
    showLoading,
    hideLoading,
    showPageLoading,
    hidePageLoading,
    copyToClipboard,
    formatNumber,
    formatCurrency,
    formatDate,
    timeAgo,
    checkPasswordStrength,
    debounce,
    throttle,
  }
  