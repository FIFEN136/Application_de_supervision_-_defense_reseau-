"""
HSR — Utilitaire d'export (CSV, JSON, PDF)
Procus Tech
"""
import csv
import json
from datetime import datetime
from pathlib import Path


class Exporter:
    """Méthodes statiques d'export des données HSR."""

    # ─────────────────────────────────────────
    # CSV
    # ─────────────────────────────────────────

    @staticmethod
    def export_events_csv(path: str, events: list):
        """Exporte les événements en CSV."""
        fields = ["id", "severity", "event_type", "host_name", "group_name",
                  "description", "port", "state_before", "state_after",
                  "occurred_at", "acknowledged", "acknowledged_by"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields, delimiter=";",
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(events)

    @staticmethod
    def export_hosts_csv(path: str, hosts: list):
        fields = ["id", "name", "ip_address", "device_type", "group_name",
                  "status", "location", "last_check"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields, delimiter=";",
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(hosts)

    @staticmethod
    def export_metrics_csv(path: str, metrics: list):
        fields = ["host_name", "metric_name", "interface", "value", "unit", "collected_at"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields, delimiter=";",
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(metrics)

    # ─────────────────────────────────────────
    # JSON
    # ─────────────────────────────────────────

    @staticmethod
    def export_json(path: str, data: list | dict, indent: int = 2):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent, default=str)

    # ─────────────────────────────────────────
    # PDF (reportlab)
    # ─────────────────────────────────────────

    @staticmethod
    def export_pdf(path: str, hosts: list, title: str = "Rapport HSR",
                   events: list = None):
        """
        Génère un rapport PDF de disponibilité.
        Requiert reportlab.
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable
            )
        except ImportError:
            raise ImportError("reportlab est requis : pip install reportlab")

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=2 * cm, rightMargin=2 * cm,
            topMargin=2 * cm, bottomMargin=2 * cm,
            title=title,
            author="HSR — Procus Tech",
        )

        styles = getSampleStyleSheet()
        story = []

        # En-tête
        style_title = ParagraphStyle(
            "hsr_title",
            fontSize=18,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#F39C12"),
            spaceAfter=6,
        )
        style_sub = ParagraphStyle(
            "hsr_sub",
            fontSize=10,
            fontName="Helvetica",
            textColor=colors.HexColor("#8B9CB0"),
            spaceAfter=16,
        )
        style_h2 = ParagraphStyle(
            "hsr_h2",
            fontSize=12,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#E8EAED"),
            spaceAfter=8,
            spaceBefore=12,
        )
        style_normal = ParagraphStyle(
            "hsr_normal",
            fontSize=9,
            fontName="Helvetica",
            textColor=colors.HexColor("#C8CDD6"),
        )

        story.append(Paragraph(title, style_title))
        story.append(Paragraph(
            f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')} — HSR Procus Tech",
            style_sub
        ))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor("#2D3340")))
        story.append(Spacer(1, 0.4 * cm))

        # Résumé
        total = len(hosts)
        online = sum(1 for h in hosts if h.get("status") == "online")
        offline = sum(1 for h in hosts if h.get("status") == "offline")
        unreachable = sum(1 for h in hosts if h.get("status") == "unreachable")
        dispo_pct = round(online / total * 100, 1) if total > 0 else 0

        story.append(Paragraph("Résumé", style_h2))
        summary_data = [
            ["Total équipements", str(total)],
            ["En ligne",          str(online)],
            ["Hors ligne",        str(offline)],
            ["Injoignables",      str(unreachable)],
            ["Disponibilité",     f"{dispo_pct}%"],
        ]
        ts = TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#20242C")),
            ("TEXTCOLOR",     (0, 0), (-1, -1), colors.HexColor("#E8EAED")),
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1),
             [colors.HexColor("#1E2228"), colors.HexColor("#20242C")]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#2D3340")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
        tbl = Table(summary_data, colWidths=[8 * cm, 5 * cm])
        tbl.setStyle(ts)
        story.append(tbl)
        story.append(Spacer(1, 0.5 * cm))

        # Tableau des hôtes
        story.append(Paragraph("Détail des équipements", style_h2))
        host_headers = ["Nom", "IP", "Type", "Groupe", "Statut", "Localisation"]
        host_rows = [host_headers]
        for h in hosts:
            host_rows.append([
                h.get("name", ""),
                h.get("ip_address", ""),
                h.get("device_type", ""),
                h.get("group_name", "") or "—",
                h.get("status", "").capitalize(),
                h.get("location", "") or "—",
            ])

        STATUS_CELL_COLORS = {
            "online":      colors.HexColor("#2ECC71"),
            "offline":     colors.HexColor("#E74C3C"),
            "unreachable": colors.HexColor("#F39C12"),
        }

        tbl_style = TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#151820")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.HexColor("#8B9CB0")),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),
             [colors.HexColor("#1E2228"), colors.HexColor("#20242C")]),
            ("TEXTCOLOR",     (0, 1), (-1, -1), colors.HexColor("#C8CDD6")),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#2D3340")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])

        col_widths = [4*cm, 3*cm, 2.5*cm, 2.5*cm, 2*cm, 3*cm]
        tbl_hosts = Table(host_rows, colWidths=col_widths, repeatRows=1)
        tbl_hosts.setStyle(tbl_style)
        story.append(tbl_hosts)

        # Événements récents si fournis
        if events:
            story.append(Spacer(1, 0.5 * cm))
            story.append(Paragraph("Événements récents", style_h2))
            evt_headers = ["Sévérité", "Hôte", "Description", "Date"]
            evt_rows = [evt_headers]
            for e in events[:50]:
                evt_rows.append([
                    (e.get("severity") or "").upper(),
                    e.get("host_name", ""),
                    (e.get("description", "") or "")[:60],
                    str(e.get("occurred_at", ""))[:16],
                ])
            tbl_evts = Table(evt_rows,
                             colWidths=[2.5*cm, 3.5*cm, 8*cm, 3*cm],
                             repeatRows=1)
            tbl_evts.setStyle(tbl_style)
            story.append(tbl_evts)

        # Pied de page
        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#2D3340")))
        story.append(Paragraph(
            "Document confidentiel — HSR Hyper-Superviseur Réseau — Procus Tech",
            style_sub
        ))

        doc.build(story)
