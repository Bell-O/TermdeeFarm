# Railway Deployment Guide

## ✅ Configuration Files

โปรเจกต์นี้พร้อมสำหรับ deploy บน Railway โดยใช้ **NIXPACKS** builder

### Files ที่จำเป็น:
- ✅ `railway.json` - Configuration สำหรับ Railway
- ✅ `Procfile` - Start command
- ✅ `requirements.txt` - Python dependencies
- ✅ `runtime.txt` - Python version (3.11.0)

## 🚀 Deploy Steps

### 1. บน Railway Dashboard

1. **New Project** → **Deploy from GitHub repo**
2. เลือก repository ของคุณ
3. Railway จะ detect อัตโนมัติ:
   - Python project (จาก `requirements.txt`)
   - NIXPACKS builder (จาก `railway.json`)
   - Start command จาก `Procfile`

### 2. Environment Variables

เพิ่มใน Railway Dashboard → Settings → Variables:

```
SECRET_KEY=your-secret-key-here (ใช้ openssl rand -hex 32)
DATABASE_URL=(จะถูกสร้างอัตโนมัติเมื่อเพิ่ม PostgreSQL)
```

### 3. Add PostgreSQL Database

1. Railway Dashboard → **+ New** → **Database** → **Add PostgreSQL**
2. Railway จะสร้าง `DATABASE_URL` อัตโนมัติ
3. Copy `DATABASE_URL` และเพิ่มเป็น environment variable

### 4. Deploy

Railway จะ deploy อัตโนมัติเมื่อ:
- Push code ใหม่
- หรือคลิก **Deploy** ใน Dashboard

## 🔧 Troubleshooting

### ถ้ายังมีปัญหา build error:

1. **ตรวจสอบว่าไม่มี Dockerfile หรือ nixpacks.toml** ใน repo (Railway จะใช้ NIXPACKS auto-detect แทน)
2. **ตรวจสอบ railway.json** ว่าใช้ `"builder": "NIXPACKS"` และไม่มี `nixpacksConfigPath`
3. **ลบไฟล์ที่ทำให้สับสน** (Dockerfile, nixpacks.toml, package.json) และ commit ใหม่
4. **ลบ nixpacks.toml จาก git** (ถ้ามี):
   ```bash
   git rm nixpacks.toml
   git commit -m "Remove nixpacks.toml, use auto-detection"
   git push
   ```

### ถ้า build fail:

1. ตรวจสอบ `requirements.txt` ว่าถูกต้อง
2. ตรวจสอบ `runtime.txt` ว่าเป็น Python version ที่รองรับ
3. ดู logs ใน Railway Dashboard → Deployments → View logs

## 📝 Notes

- Railway ใช้ NIXPACKS builder ซึ่งจะ detect Python project อัตโนมัติ
- ไม่ต้องใช้ Dockerfile (NIXPACKS จัดการให้)
- `Procfile` และ `railway.json` จะบอก Railway ว่าต้องรันอะไร

