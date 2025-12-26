# Prompt สำหรับแก้ไข CSS - Termdee Farm

## 🎯 วัตถุประสงค์
แก้ไขและปรับปรุง CSS ของระบบ Termdee Farm ให้รองรับมือถือและมี UI/UX ที่ดีขึ้น

## 📋 ข้อมูลโปรเจกต์

### โครงสร้าง CSS
- **ไฟล์หลัก**: `static/css/style.css`
- **Framework**: Custom CSS (ไม่ใช้ Bootstrap/Tailwind)
- **Design System**: ใช้ CSS Variables สำหรับ colors, spacing, shadows
- **Responsive**: ใช้ Media Queries สำหรับ mobile/tablet/desktop

### CSS Variables ที่ใช้
```css
--primary-color: #2563eb
--success-color: #10b981
--warning-color: #f59e0b
--danger-color: #ef4444
--bg-color: #f8fafc
--text-primary: #1e293b
--space-xs, --space-sm, --space-md, --space-lg, --space-xl
--radius-sm, --radius, --radius-lg
--shadow-xs, --shadow-sm, --shadow-md, --shadow-lg
```

### Breakpoints
- **Desktop**: > 1024px
- **Tablet**: 768px - 1024px
- **Mobile**: < 768px
- **Small Mobile**: < 480px

## 🔧 ข้อกำหนดสำหรับการแก้ไข CSS

### 1. Responsive Design
- **ตาราง (Tables)**: ต้องแปลงเป็น card layout บนมือถือ
  - ใช้ `data-label` attributes สำหรับแสดงชื่อคอลัมน์
  - แสดง label ด้านซ้าย ข้อมูลด้านขวา
  - ปุ่มจัดเรียงแนวตั้ง
  
- **Navigation**: 
  - Mobile menu ต้องเป็น hamburger menu
  - Menu ต้อง slide down เมื่อเปิด
  
- **Cards**: 
  - Padding และ margin ต้องปรับตามขนาดหน้าจอ
  - Font size ต้องลดลงบนมือถือ

### 2. Table Styling
- **Alignment**:
  - ตัวเลข: `text-align: right` + `font-variant-numeric: tabular-nums`
  - ข้อความ: `text-align: left` (default)
  - สถานะ/จัดการ: `text-align: center`
  
- **Mobile View**:
  ```css
  @media (max-width: 768px) {
    .table, .table thead, .table tbody, .table th, .table td, .table tr {
      display: block;
    }
    .table thead { display: none; }
    .table td {
      padding-left: 40%;
      position: relative;
    }
    .table td:before {
      content: attr(data-label);
      position: absolute;
      left: 0;
      width: 35%;
    }
  }
  ```

### 3. Typography
- **Font Sizes**:
  - Desktop: 1rem (16px) base
  - Tablet: 0.9375rem (15px)
  - Mobile: 0.875rem (14px)
  - Small Mobile: 0.75rem (12px)

### 4. Spacing
- ใช้ CSS Variables สำหรับ spacing
- Mobile: ลด spacing ลง 20-30%
- Padding ใน cards: `var(--space-md)` → `var(--space-sm)` บนมือถือ

### 5. Colors & Contrast
- ต้องผ่าน WCAG AA (contrast ratio 4.5:1 สำหรับ text)
- รองรับ dark mode (ใช้ `@media (prefers-color-scheme: dark)`)
- ใช้ CSS Variables สำหรับ colors

### 6. Buttons
- Mobile: ปุ่มต้องเต็มความกว้าง (`width: 100%`)
- Button groups: จัดเรียงแนวตั้งบนมือถือ
- Touch targets: อย่างน้อย 44x44px

### 7. Forms
- Input fields: `font-size: 16px` บนมือถือ (ป้องกัน zoom)
- Labels: ต้องชัดเจนและอ่านง่าย
- Error states: ใช้สี danger และแสดงข้อความชัดเจน

## 📝 Template Structure

### ตารางที่ต้องมี responsive
1. `admin/orders.html` - ตารางออเดอร์
2. `admin/farmers.html` - ตารางคนฟาร์มและแอดมิน
3. `farmer/leaderboard.html` - ตาราง leaderboard
4. `admin/activity.html` - ตารางกิจกรรม
5. `farmer/tasks.html` - ตารางงาน

### Components ที่ต้องปรับ
- `.table` และ `.table-responsive`
- `.card` และ `.card-header`
- `.btn` และ `.btn-group`
- `.form-control` และ `.form-group`
- `.navbar` และ `.nav-menu`
- `.badge`
- `.progress` และ `.progress-bar`

## 🎨 Design Principles

### 1. Consistency
- ใช้ CSS Variables เสมอ
- ใช้ spacing scale เดียวกัน
- ใช้ border-radius เดียวกัน

### 2. Performance
- หลีกเลี่ยง `!important` ถ้าไม่จำเป็น
- ใช้ CSS transforms แทน position changes
- ใช้ `will-change` สำหรับ animations

### 3. Accessibility
- ใช้ semantic HTML
- รองรับ keyboard navigation
- มี focus states ที่ชัดเจน

### 4. Mobile First
- เขียน CSS สำหรับ mobile ก่อน
- ใช้ `min-width` media queries
- ทดสอบบนหน้าจอจริง

## 🔍 ปัญหาที่พบบ่อย

### 1. Tables บนมือถือ
- **ปัญหา**: ตารางกว้างเกินไป ทำให้ต้อง scroll แนวนอน
- **แก้ไข**: ใช้ card layout บนมือถือ

### 2. Text Alignment
- **ปัญหา**: ตัวเลขไม่ตรงกัน
- **แก้ไข**: ใช้ `text-align: right` + `tabular-nums`

### 3. Button Groups
- **ปัญหา**: ปุ่มซ้อนกันบนมือถือ
- **แก้ไข**: ใช้ `flex-direction: column` บนมือถือ

### 4. Navigation
- **ปัญหา**: Menu ไม่ responsive
- **แก้ไข**: ใช้ hamburger menu + slide animation

## 📋 Checklist สำหรับการแก้ไข

- [ ] ทุกตารางมี `.table-responsive` wrapper
- [ ] ทุก `<td>` มี `data-label` attribute
- [ ] Alignment ถูกต้อง (ตัวเลขชิดขวา, ข้อความชิดซ้าย)
- [ ] Mobile view แสดงเป็น card layout
- [ ] Font sizes ปรับตามขนาดหน้าจอ
- [ ] Spacing ปรับตามขนาดหน้าจอ
- [ ] Buttons มีขนาดพอสำหรับ touch
- [ ] Forms รองรับมือถือ
- [ ] Navigation เป็น hamburger menu บนมือถือ
- [ ] ทดสอบบนหน้าจอจริง (iPhone, Android)

## 🚀 ตัวอย่าง Prompt ที่ใช้ได้

```
ฉันต้องการแก้ไข CSS ของระบบ Termdee Farm ให้รองรับมือถือดีขึ้น

โปรดทำตามนี้:
1. ตรวจสอบตารางทั้งหมดและเพิ่ม responsive styles
2. ปรับ alignment ให้ตัวเลขชิดขวา ข้อความชิดซ้าย
3. เพิ่ม mobile card layout สำหรับตาราง
4. ปรับ font sizes และ spacing สำหรับมือถือ
5. ตรวจสอบว่า buttons มีขนาดพอสำหรับ touch
6. ทดสอบ responsive design บนหน้าจอต่างๆ

ใช้ CSS Variables ที่มีอยู่แล้ว และไม่ใช้ !important ถ้าไม่จำเป็น
```

## 📚 Resources

- CSS Variables: ใช้ `:root` สำหรับ global variables
- Media Queries: ใช้ `@media (max-width: 768px)` สำหรับ mobile
- Flexbox: ใช้สำหรับ layout และ alignment
- Grid: ใช้สำหรับ complex layouts
- Transitions: ใช้ `var(--transition)` สำหรับ animations

## ⚠️ ข้อควรระวัง

1. **ไม่ใช้ inline styles** - ใช้ CSS classes แทน
2. **ไม่ hardcode colors** - ใช้ CSS Variables
3. **ไม่ใช้ fixed widths** - ใช้ responsive units (%, rem, em)
4. **ไม่ลืม test** - ทดสอบบนหน้าจอจริงเสมอ
5. **ไม่ใช้ vendor prefixes** - ใช้ autoprefixer แทน

---

**หมายเหตุ**: Prompt นี้ใช้สำหรับให้ AI หรือ developer อื่นๆ เข้าใจโครงสร้างและข้อกำหนดของ CSS ในโปรเจกต์นี้

