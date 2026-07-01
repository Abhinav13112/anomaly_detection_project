import os
import json
import pandas as pd
from datetime import datetime

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_csv_report(threats, filepath):
    """Generates a CSV report from a list of threat dictionaries."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    df = pd.DataFrame(threats)
    if df.empty:
        df = pd.DataFrame(columns=["timestamp", "ip_address", "status_code", "message", "threat_type", "severity", "confidence", "status"])
    df.to_csv(filepath, index=False)
    return filepath

def generate_json_report(threats, filepath):
    """Generates a JSON report from a list of threat dictionaries."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(threats, f, indent=4)
    return filepath

def generate_excel_report(summary_stats, threats, filepath):
    """Generates a detailed multi-sheet Excel report using openpyxl."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # 1. Summary sheet data
    summary_data = {
        "Metric": [
            "Report Generated Time", 
            "Total Logs Processed", 
            "Total Threats Detected", 
            "Avg Threat Risk Score", 
            "Avg Detection Confidence",
            "Open Security Action Items"
        ],
        "Value": [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            summary_stats.get("total_logs", 0),
            summary_stats.get("total_anomalies", 0),
            f"{summary_stats.get('avg_risk', 0.0)} / 100",
            f"{summary_stats.get('avg_confidence', 0.0)}%",
            summary_stats.get("open_threats", 0)
        ]
    }
    df_summary = pd.DataFrame(summary_data)
    
    # 2. Detailed threats data
    df_threats = pd.DataFrame(threats)
    if df_threats.empty:
        df_threats = pd.DataFrame(columns=["id", "timestamp", "ip_address", "status_code", "message", "threat_type", "severity", "confidence", "status", "remediation"])
    else:
        # Reorder/clean columns for readability
        cols = ["id", "timestamp", "ip_address", "status_code", "message", "threat_type", "severity", "confidence", "status", "remediation"]
        existing_cols = [c for c in cols if c in df_threats.columns]
        df_threats = df_threats[existing_cols]

    # 3. Recommendations list sheet
    recs = []
    if not df_threats.empty:
        grouped = df_threats.groupby("threat_type")
        for threat_type, group in grouped:
            # Get the remediation from first item
            first_rem = group.iloc[0].get("remediation", "")
            clean_rem = first_rem.replace("✔ ", "").split("\n")
            for item in clean_rem:
                if item.strip():
                    recs.append({
                        "Threat Type": threat_type,
                        "Severity": group.iloc[0].get("severity", "Medium"),
                        "Action Plan Item": item.strip()
                    })
    df_recs = pd.DataFrame(recs)
    if df_recs.empty:
        df_recs = pd.DataFrame(columns=["Threat Type", "Severity", "Action Plan Item"])

    # Write sheets
    with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
        df_summary.to_excel(writer, sheet_name="Executive Summary", index=False)
        df_threats.to_excel(writer, sheet_name="Security Alerts", index=False)
        df_recs.to_excel(writer, sheet_name="Remediation Guide", index=False)
        
    return filepath

def generate_pdf_report(summary_stats, threats, filepath):
    """Generates a professional executive-ready PDF report using ReportLab."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Palette and Typography styles
    primary_color = colors.HexColor("#1e3a8a") # Dark navy blue
    secondary_color = colors.HexColor("#0f766e") # Teal accent
    alert_color = colors.HexColor("#b91c1c") # Red alert
    text_color = colors.HexColor("#1f2937") # Gray-800
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=primary_color,
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=10,
        textColor=colors.HexColor("#4b5563"),
        spaceAfter=20
    )
    
    h1_style = ParagraphStyle(
        'HeadingSection',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=primary_color,
        spaceBefore=15,
        spaceAfter=8,
        borderColor=primary_color,
        borderWidth=0.5,
        borderPadding=4
    )
    
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=text_color,
        spaceAfter=6,
        leading=14
    )
    
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=colors.white
    )
    
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=text_color,
        leading=10
    )
    
    table_cell_bold_style = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        textColor=text_color,
        leading=10
    )

    story = []
    
    # --- HEADER SECTION ---
    story.append(Paragraph("LOGSENTRIX AI - SECURITY ANALYSIS REPORT", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Confidential Security Audit Report", subtitle_style))
    story.append(Spacer(1, 10))
    
    # --- EXECUTIVE SUMMARY ---
    story.append(Paragraph("1. Executive Summary", h1_style))
    intro_p = ("This threat assessment report summarizes the results of the automated AI-driven log analysis pipeline. "
               "Using an unsupervised Isolation Forest machine learning model alongside cybersecurity threat intelligence rulesets, "
               "incoming system logs were parsed to evaluate overall infrastructure health, risk indexes, and anomalies.")
    story.append(Paragraph(intro_p, body_style))
    
    # Summary Metrics Table
    summary_table_data = [
        [Paragraph("<b>Security Key Performance Indicator</b>", table_header_style), Paragraph("<b>Audit Metric Value</b>", table_header_style)],
        [Paragraph("Total System Logs Analyzed", table_cell_bold_style), Paragraph(str(summary_stats.get("total_logs", 0)), table_cell_style)],
        [Paragraph("Identified Threat Anomalies", table_cell_bold_style), Paragraph(str(summary_stats.get("total_anomalies", 0)), table_cell_style)],
        [Paragraph("Calculated Infrastructure Risk Score", table_cell_bold_style), Paragraph(f"{summary_stats.get('avg_risk', 0.0)} / 100", table_cell_style)],
        [Paragraph("Mean Model Prediction Confidence", table_cell_bold_style), Paragraph(f"{summary_stats.get('avg_confidence', 0.0)}%", table_cell_style)],
        [Paragraph("Active Unresolved Alerts", table_cell_bold_style), Paragraph(str(summary_stats.get("open_threats", 0)), table_cell_style)]
    ]
    
    summary_table = Table(summary_table_data, colWidths=[250, 250])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#f3f4f6"), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#d1d5db")),
        ('BOTTOMPADDING', (0,1), (-1,-1), 6),
        ('TOPPADDING', (0,1), (-1,-1), 6),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 15))
    
    # --- THREAT ANALYSIS SUMMARY ---
    story.append(Paragraph("2. Detected Cybersecurity Threats", h1_style))
    if not threats:
        story.append(Paragraph("<b>No anomalies or threats were detected in the log files. The infrastructure operates within normal statistical bounds.</b>", body_style))
    else:
        # Group and tally
        t_df = pd.DataFrame(threats)
        threat_counts = t_df['threat_type'].value_counts().to_dict()
        severity_counts = t_df['severity'].value_counts().to_dict()
        
        details_txt = f"A total of <b>{len(threats)}</b> threat alerts were raised. "
        details_txt += "The anomalies fell into the following categories: "
        details_txt += ", ".join([f"{k} ({v})" for k, v in threat_counts.items()])
        details_txt += ". Severity distribution is: "
        details_txt += ", ".join([f"{k} ({v})" for k, v in severity_counts.items()])
        details_txt += "."
        story.append(Paragraph(details_txt, body_style))
        story.append(Spacer(1, 10))
        
        # Threats List Table
        threats_table_data = [
            [
                Paragraph("<b>Timestamp</b>", table_header_style), 
                Paragraph("<b>Source IP</b>", table_header_style), 
                Paragraph("<b>Threat Type</b>", table_header_style), 
                Paragraph("<b>Severity</b>", table_header_style), 
                Paragraph("<b>Confidence</b>", table_header_style),
                Paragraph("<b>Code</b>", table_header_style)
            ]
        ]
        
        for t in threats[:15]: # Show top 15 in PDF to keep pages readable
            sev = t.get('severity', 'Medium')
            sev_color = alert_color if sev == 'Critical' else (colors.HexColor("#ea580c") if sev == 'High' else colors.HexColor("#eab308"))
            
            threats_table_data.append([
                Paragraph(t.get('timestamp', ''), table_cell_style),
                Paragraph(t.get('ip_address', ''), table_cell_bold_style),
                Paragraph(t.get('threat_type', ''), table_cell_style),
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", table_cell_style),
                Paragraph(f"{t.get('confidence', 0.0)}%", table_cell_style),
                Paragraph(str(t.get('status_code', '')), table_cell_style),
            ])
            
        t_widths = [100, 80, 120, 70, 70, 40]
        threats_table = Table(threats_table_data, colWidths=t_widths)
        threats_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), secondary_color),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,0), 4),
            ('TOPPADDING', (0,0), (-1,0), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#f9fafb"), colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ('BOTTOMPADDING', (0,1), (-1,-1), 4),
            ('TOPPADDING', (0,1), (-1,-1), 4),
        ]))
        
        story.append(threats_table)
        if len(threats) > 15:
            story.append(Spacer(1, 5))
            story.append(Paragraph(f"<i>* Showing top 15 of {len(threats)} total alerts in the PDF report. Please download JSON/Excel for full details.</i>", body_style))
            
    story.append(Spacer(1, 15))
    
    # --- REMEDIATION CHECKLIST ---
    story.append(Paragraph("3. Recommended Remediation Action Items", h1_style))
    if not threats:
        story.append(Paragraph("No remediation required. Regular monitoring advised.", body_style))
    else:
        # Collect top unique remediation items
        unique_threats = pd.DataFrame(threats)['threat_type'].unique()
        story.append(Paragraph("Security team should execute the following actions to secure system endpoints:", body_style))
        story.append(Spacer(1, 5))
        
        counter = 1
        for ut in unique_threats[:3]: # limit to top 3 threat types in PDF to save space
            # Find remediation list for this threat type
            match_t = next((item for item in threats if item['threat_type'] == ut), None)
            if match_t and match_t.get('remediation'):
                recs_list = match_t['remediation'].replace("✔ ", "").split("\n")
                story.append(Paragraph(f"<b>For {ut}:</b>", body_style))
                for rec_item in recs_list[:3]: # show top 3 recommendations per threat
                    if rec_item.strip():
                        story.append(Paragraph(f"   [{counter}] {rec_item.strip()}", body_style))
                        counter += 1
                story.append(Spacer(1, 5))

    doc.build(story)
    return filepath
