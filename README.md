# LAN Sentinel

A student concept paper website for **Development of an AI-Based Network Intrusion Detection System for Local Area Networks Using Traffic Anomaly Analysis**. It is built on the EduBoost Bootstrap 5.3.3 template and works fully offline. Just open it in your browser.

**Researchers:** Congrejilla, Mark Jhon; Gulle, Kevin Ian B.; Oras, Nathaniel; Sevilla, Errol P.

**Pages included:** Home, About, Literature, Dashboard, Contact, Login, Sign Up.

> Concept paper: [docs/Concept_Paper.docx](docs/Concept_Paper.docx) | Template guide: [docs/Bootstrap_Student_Guide.pdf](docs/Bootstrap_Student_Guide.pdf)

---

## Quick Start

1. Download or clone this project to your computer.
2. Open the folder in **VS Code** (or any code editor).
3. Double-click `index.html` to open it in your browser.
4. Click through the pages. Change something, save, and press **Ctrl + F5**.

## Project Structure

```
lan-sentinel/
├── index.html               Home page
├── pages/
│   ├── about.html           Background, problem, objectives, significance, scope
│   ├── literature.html      Related studies, synthesis, references
│   ├── dashboard.html       Network alert dashboard (sample data)
│   ├── contact.html         Researchers and contact form
│   ├── login.html           Login page (layout only)
│   └── signup.html          Sign up page (layout only)
├── assets/
│   ├── css/
│   │   ├── bootstrap.min.css        Bootstrap styles (do NOT edit)
│   │   ├── bootstrap-icons.min.css  Icon styles (do NOT edit)
│   │   ├── fonts/                   Icon fonts
│   │   └── style.css                YOUR custom styles (edit this one)
│   ├── js/
│   │   └── bootstrap.bundle.min.js  Bootstrap JavaScript (do NOT edit)
│   └── images/                      Favicon and SVG illustrations
├── docs/
│   ├── Concept_Paper.docx
│   └── Bootstrap_Student_Guide.pdf
└── README.md
```

**Rule of thumb:** Edit the HTML files and `style.css`. Do not edit files ending in `.min.css` or `.min.js`.

## Change the Look

- **Colors:** edit `--brand`, `--brand-dark` and `--ink` at the top of `assets/css/style.css`.
- **Site name:** search for `LAN Sentinel` in each HTML file.
- **Images:** put pictures in `assets/images/` and update the `src` in the HTML.

## Notes

- The dashboard shows **sample data**. No detection is running yet.
- Login, Sign Up and the contact form are layout only. They do not send or store anything.

## Credits

- Bootstrap 5.3.3 and Bootstrap Icons 1.11.3 (MIT License)
- Template structure from EduBoost Bootstrap Template by chardestrada
