# คำแนะนำการ Deploy บน Render

## ข้อมูลที่ต้องใส่ใน Render Dashboard

### 1. Name
```
termdee-farm
```

### 2. Language
```
Python 3
```

### 3. Branch
```
main
```
(หรือ branch ที่คุณใช้)

### 4. Region
```
Singapore (Southeast Asia)
```
(หรือ region ที่ใกล้ที่สุด)

### 5. Root Directory
```
(เว้นว่างไว้ - ไม่ต้องใส่)
```

### 6. Build Command
```
pip install -r requirements.txt
```

### 7. Start Command
```
gunicorn --bind 0.0.0.0:$PORT --workers 2 --timeout 120 app:app
```

## Environment Variables (ต้องเพิ่มใน Render Dashboard)

1. **SECRET_KEY** (Generate new secret key)
   - คลิก "Generate" เพื่อสร้าง secret key อัตโนมัติ
   - หรือใส่ค่าที่ต้องการเอง

2. **FLASK_ENV** (Optional)
   - Value: `production`

## Database (แนะนำให้ใช้ PostgreSQL)

### วิธีที่ 1: สร้าง PostgreSQL Database ใน Render
1. ไปที่ "New" → "PostgreSQL"
2. ตั้งชื่อ database (เช่น `termdee-farm-db`)
3. Render จะสร้าง `DATABASE_URL` อัตโนมัติ
4. เพิ่ม Environment Variable:
   - **DATABASE_URL** - จะถูกสร้างอัตโนมัติเมื่อเชื่อม database

### วิธีที่ 2: ใช้ render.yaml (Auto-deploy)
- ไฟล์ `render.yaml` จะสร้าง database และเชื่อมต่ออัตโนมัติ

## หมายเหตุสำคัญ

- Render จะใช้ port จาก environment variable `$PORT` อัตโนมัติ
- ถ้าใช้ SQLite (ไม่แนะนำสำหรับ production) อาจมีปัญหาเรื่อง persistent storage
- **แนะนำให้ใช้ PostgreSQL สำหรับ production**
- หลังจาก deploy แล้ว ต้อง login เป็น admin และเปลี่ยนรหัสผ่านทันที
- Default admin: `admin` / `admin123` (เปลี่ยนทันที!)

## การใช้งาน render.yaml (แนะนำ)

ถ้าคุณใช้ `render.yaml`:
1. Push code ไปที่ GitHub
2. ใน Render Dashboard → "New" → "Blueprint"
3. เลือก repository และ branch
4. Render จะสร้าง service และ database อัตโนมัติ

## Troubleshooting

- ถ้า build fail: ตรวจสอบว่า requirements.txt มี dependencies ครบ
- ถ้า database error: ตรวจสอบว่า DATABASE_URL ถูกตั้งค่าแล้ว
- ถ้า app ไม่ start: ตรวจสอบ logs ใน Render Dashboard
