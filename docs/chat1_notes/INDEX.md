
### For First-Time Users (Read in this order):

1. **START_HERE.md** ⭐⭐⭐
   - Quick overview of everything
   - What you got
   - Quick start (3 steps)
   - Verification checklist

2. **QUICKSTART.md**
   - Fast setup commands
   - Testing commands
   - Troubleshooting

3. **WINDOWS_SETUP.md** (Windows users)
   - Detailed Docker Desktop installation
   - VS Code setup
   - Step-by-step building
   - Screenshot guide
   - Common issues

4. **COMPLETE_GUIDE.md**
   - Comprehensive overview
   - Technical details
   - Submission instructions
   - Full checklist

---

## 📖 Documentation Categories

### 🚀 Getting Started
| File | Purpose | When to Use |
|------|---------|-------------|
| **START_HERE.md** | First stop, quick overview | Right now! |
| **QUICKSTART.md** | Fast reference | When you know what you're doing |
| **TESTING_COMMANDS.md** | Copy-paste commands | When testing |

### 💻 Platform-Specific Setup
| File | Purpose | When to Use |
|------|---------|-------------|
| **WINDOWS_SETUP.md** | Windows/VS Code guide | You're on Windows |
| build_and_test.sh | Linux/Mac automation | You're on Linux/Mac |

### 📝 For Your Report
| File | Purpose | When to Use |
|------|---------|-------------|
| **WRITEUP.md** ⭐ | Complete solution walkthrough | Creating your PDF report |
| **ARCHITECTURE.md** | Visual diagrams & flow | Understanding the challenge |

### 🎮 Challenge Details
| File | Purpose | When to Use |
|------|---------|-------------|
| **README.md** | Challenge overview | Understanding what it does |
| **CTFD_CHALLENGE.md** | CTFd deployment | Deploying to CTF platform |
| **COMPLETE_GUIDE.md** | Everything in one place | Deep dive reference |

## 📦 File Categories by Type

### 📄 Core Challenge Files
```
✅ challenge.c              - Source code (must submit)
✅ Dockerfile               - Container config (must submit)
✅ docker-entrypoint.sh     - Startup script (must submit)
✅ reverse_me               - Compiled binary
```

### 🐍 Solution Scripts
```
✅ keyfinder.py             - Automated solver (must submit)
✅ solution.py              - Solution demo (optional submit)
✅ build_and_test.sh        - Test automation (Linux/Mac)
```

### 📚 Documentation Files
```
📖 START_HERE.md            - Quick start guide
📖 QUICKSTART.md            - Fast reference
📖 WINDOWS_SETUP.md         - Windows detailed guide
📖 WRITEUP.md               - ⭐ Use for your report!
📖 ARCHITECTURE.md          - Visual diagrams
📖 COMPLETE_GUIDE.md        - Comprehensive guide
📖 README.md                - Challenge overview
📖 CTFD_CHALLENGE.md        - Platform deployment
📖 TESTING_COMMANDS.md      - Command reference
```

---

## 🎯 Quick Navigation by Task

### "I want to build and test the challenge"
1. Read: **QUICKSTART.md**
2. Follow: **TESTING_COMMANDS.md**
3. If issues: **WINDOWS_SETUP.md** (troubleshooting section)

### "I want to write my report"
1. Read: **WRITEUP.md** (this is your template!)
2. Reference: **ARCHITECTURE.md** (for diagrams)
3. Follow: **COMPLETE_GUIDE.md** (submission section)

### "I want to understand how it works"
1. Read: **README.md**
2. Study: **ARCHITECTURE.md**
3. Deep dive: **WRITEUP.md** (exploitation section)

### "I'm having problems"
1. Check: **WINDOWS_SETUP.md** (troubleshooting)
2. Verify: **TESTING_COMMANDS.md** (verification checklist)
3. Review: **QUICKSTART.md** (quick fixes)

### "I want to deploy to CTFd"
1. Read: **CTFD_CHALLENGE.md**
2. Reference: **README.md** (deployment section)

---

## 📋 What to Submit

### Submission File 1: Challenge ZIP
**Filename:** `rev-challenge-files.zip`

**Must include:**
- ✅ challenge.c
- ✅ Dockerfile
- ✅ docker-entrypoint.sh
- ✅ README.md
- ✅ keyfinder.py
- ✅ solution.py

**Optional but recommended:**
- build_and_test.sh
- reverse_me (compiled binary)

### Submission File 2: Report PDF
**Filename:** `YourRollNumber-YourFullName-A04-YourSection.pdf`

**Based on:** WRITEUP.md

**Must include:**
- Challenge description
- Enumeration (with screenshots)
- Vulnerability identification
- Exploitation (with screenshots)
- Flag retrieval (with screenshots)
- Tools used
- Payloads used
- Summary

**Screenshot requirements:**
- ✅ FULL SCREEN with taskbar visible
- ✅ At least 9 screenshots
- ✅ Clear and readable
- ✅ Shows complete workflow

---

## 🔑 Key Information Quick Reference

| Item | Value |
|------|-------|
| **Challenge Name** | Crack Me If You Can |
| **Category** | Reverse Engineering |
| **Difficulty** | Hard |
| **Points** | 500 |
| **Valid Key** | `Rav3r5a_abp1Sg7!` |
| **Flag** | `EHCP{R3v3rs3_M4st3r_Un10ck3d!}` |
| **Binary Type** | ELF 64-bit, stripped |
| **Docker Image** | `rev-challenge` |
| **Binary Name** | `reverse_me` |

---

## 🛠️ Tools Reference

### Required Tools
- Docker Desktop (Windows/Mac)
- Ghidra (FREE decompiler)
- Python 3.x (for solver)

### Optional Tools
- VS Code (recommended editor)
- IDA Free (alternative decompiler)
- GDB (dynamic analysis)
- radare2 (alternative analysis)

### Tool Download Links
- Docker: https://www.docker.com/products/docker-desktop/
- Ghidra: https://ghidra-sre.org/
- Python: https://python.org
- VS Code: https://code.visualstudio.com/

---

## ⏱️ Time Estimates

| Task | Time |
|------|------|
| Docker installation | 30 min |
| Build & test | 10 min |
| Binary analysis (Ghidra) | 30-60 min |
| Take screenshots | 20 min |
| Write report | 1-2 hours |
| Create submissions | 15 min |
| **TOTAL** | **2.5-3.5 hours** |

---

## ✅ Pre-Submission Checklist

### Technical
- [ ] Docker Desktop installed and running
- [ ] Challenge builds without errors
- [ ] Wrong key test shows "Wrong key!"
- [ ] Correct key test shows flag
- [ ] Binary extracted successfully
- [ ] Ghidra analysis complete
- [ ] Solver script runs and finds key

### Documentation
- [ ] All screenshots taken (FULL SCREEN!)
- [ ] Screenshots include taskbar
- [ ] PDF report complete
- [ ] Based on WRITEUP.md structure
- [ ] All sections filled
- [ ] Screenshots properly placed

### Submission Files
- [ ] ZIP file created
- [ ] ZIP contains all required files
- [ ] ZIP is 20-50 KB size
- [ ] PDF created from WRITEUP.md
- [ ] PDF has all screenshots
- [ ] Files named correctly
- [ ] Verified naming convention

### Before Upload
- [ ] Both files ready
- [ ] Checked file sizes (ZIP ~30KB, PDF ~5-15MB)
- [ ] Verified PDF opens correctly
- [ ] Verified ZIP extracts correctly
- [ ] Current time before deadline
- [ ] Google Classroom open and ready

**Deadline:** March 28, 2026, 03:59:59 PM

---

## 🎓 Learning Outcomes

After completing this assignment, you will have learned:

✅ **Technical Skills:**
- Binary analysis with Ghidra
- ELF file structure understanding
- Anti-debugging techniques
- String obfuscation methods
- Constraint solving
- Python scripting for automation
- Docker containerization

✅ **Tools Proficiency:**
- Ghidra (professional decompiler)
- Docker (containerization)
- Python (scripting)
- Git/bash (command line)

✅ **Methodology:**
- Systematic enumeration
- Static vs dynamic analysis
- Documentation practices
- Professional report writing

---

## 💡 Pro Tips

### For Building
1. Always run Docker Desktop first
2. Use PowerShell, not CMD
3. Copy commands exactly from TESTING_COMMANDS.md
4. If build fails, check line endings

### For Analysis
1. Let Ghidra auto-analyze completely
2. Start from main() and work backwards
3. Document constraints as you find them
4. Use Python for solving, not manual calculation

### For Screenshots
1. Take them as you go, not at the end
2. FULL SCREEN means taskbar visible!
3. Clear, readable text
4. Show complete commands and outputs
5. Number them for reference

### For Report
1. Use WRITEUP.md as your template
2. Add screenshots inline with text
3. Explain what each screenshot shows
4. Include all command outputs
5. Proofread before exporting

### For Submission
1. Triple-check filenames
2. Test opening files after creating them
3. Submit 30 minutes before deadline
4. Keep backup copies

---

## 🎉 You're Ready!

**Everything is prepared and tested. Just:**

1. ✅ Read START_HERE.md
2. ✅ Follow QUICKSTART.md or WINDOWS_SETUP.md
3. ✅ Take screenshots (FULL SCREEN!)
4. ✅ Create PDF from WRITEUP.md
5. ✅ Create ZIP with source files
6. ✅ Submit before deadline

**Good luck with your assignment!**

---

## 📞 Documentation Structure

```
Documentation Tree:
│
├── START_HERE.md ⭐⭐⭐ (Read this first!)
│   └── Quick overview + 3-step start
│
├── QUICKSTART.md
│   └── Fast commands + quick reference
│
├── WINDOWS_SETUP.md (Windows users)
│   └── Detailed setup + troubleshooting
│
├── COMPLETE_GUIDE.md
│   └── Everything in one place
│
├── WRITEUP.md ⭐⭐⭐ (Use for your report!)
│   └── Complete solution walkthrough
│
├── ARCHITECTURE.md
│   └── Visual diagrams + system flow
│
├── TESTING_COMMANDS.md
│   └── Copy-paste ready commands
│
├── README.md
│   └── Challenge overview
│
└── CTFD_CHALLENGE.md
    └── Platform deployment guide
```

---

**Version:** 1.0  
**Created:** March 28, 2026  
**Status:** Complete and Ready  
**Last Updated:** March 28, 2026  
**Assignment:** EHCP Assignment 4  
**Deadline:** March 28, 2026, 03:59:59 PM
