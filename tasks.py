import subprocess
import tempfile
import json

from flask_mail import Message
from models import db, Queries

def run_analysis_task(query_id, url, email):
    from app import app
    from app import mail
    import markdown
    with app.app_context():
        new_query = db.session.get(Queries, query_id)
        new_query.status = 0  # in progress
        db.session.commit()

        try:
            CATEGORIES = [
                'accessibility',
                'best-practices',
                'performance',
                'seo'
            ]

            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmpfile:
                tmpfile_path = tmpfile.name

            subprocess.run([
                'lighthouse',
                url,
                '--output=json',
                f'--output-path={tmpfile_path}',
                '--chrome-flags="--headless"'
            ], check=True)

            with open(tmpfile_path, 'r') as f:
                lighthouse_json = json.load(f)
                scores = {category: lighthouse_json['categories'][category]['score'] for category in CATEGORIES}
                audits = lighthouse_json.get('audits', {})
                categories = lighthouse_json.get('categories', {})
                category_groups = lighthouse_json.get('categoryGroups', {})
                category_audits = {}

                def get_display(audit):
                    mode = audit.get('scoreDisplayMode', '')
                    score = audit.get('score')
                    display_value = audit.get('displayValue', '')
                    if mode == 'binary':
                        return '✔️' if score == 1 else '❌'
                    elif mode == 'numeric':
                        return display_value if display_value else score
                    elif mode == 'informative':
                        return display_value
                    elif mode == 'notApplicable':
                        return 'Not Applicable'
                    else:
                        return display_value if display_value else score

                for cat_key, cat_obj in categories.items():
                    cat_title = cat_obj.get('title', cat_key)
                    audit_refs = cat_obj.get('auditRefs', [])
                    cat_groups = {}

                    for ref in audit_refs:
                        audit_id = ref.get('id')
                        group_id = ref.get('group')
                        group_title = category_groups.get(group_id, {}).get('title', group_id) if group_id else None

                        audit = audits.get(audit_id, {})
                        audit_data = {
                            'title': markdown.markdown(audit.get('title', '')),
                            'description': markdown.markdown(audit.get('description', '')),
                            'score': audit.get('score'),
                            'scoreDisplayMode': audit.get('scoreDisplayMode', ''),
                            'displayValue': get_display(audit),
                            'details': audit.get('details', None)
                        }

                        if group_title:
                            if group_title not in cat_groups:
                                cat_groups[group_title] = []
                            cat_groups[group_title].append(audit_data)
                        else:
                            if 'Ungrouped' not in cat_groups:
                                cat_groups['Ungrouped'] = []
                            cat_groups['Ungrouped'].append(audit_data)

                    category_audits[cat_key] = {
                        'title': cat_title,
                        'groups': cat_groups
                    }

            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as zap_tmpfile:
                zap_tmpfile_path = zap_tmpfile.name

            zap_command = [
                '/Users/rajat/Dev/HackYugma/ZAP_2.16.1/zap.sh',
                '-cmd',
                '-quickurl', url,
                '-quickout', zap_tmpfile_path,
                '-quickprogress'
            ]

            subprocess.run(zap_command, check=True)

            with open(zap_tmpfile_path, 'r') as zap_file:
                zap_json = json.load(zap_file)
                severity_map = {
                    "3": "High",
                    "2": "Medium",
                    "1": "Low",
                    "0": "Informational"
                }
                alerts_by_severity = {
                    "High": [],
                    "Medium": [],
                    "Low": [],
                    "Informational": []
                }
                for site in zap_json.get("site", []):
                    for alert in site.get("alerts", []):
                        severity = severity_map.get(alert.get("riskcode", "0"), "Informational")
                        alerts_by_severity[severity].append(alert)

            new_query.scores = json.dumps(scores)
            new_query.performance = json.dumps(category_audits)
            new_query.security = json.dumps(alerts_by_severity)
            new_query.status = 1  # completed
            db.session.commit()
            try:
                msg = Message(
                    subject='Your Analysis is Complete',
                    recipients=[email],
                    body='Your analysis has been completed successfully.',
                    sender="vulner@rajatshenoi.pw"
                )
                mail.send(msg)
            except Exception as f:
                print("FAILED", f)
                app.logger.info(f"Failed to send email: {f}")
        except Exception as e:
            new_query.status = 2  # failed
            db.session.commit()
            try:
                msg = Message(
                    subject='Your Analysis has Failed',
                    recipients=[email],
                    body='Your analysis has failed. This is most likely an error, please try again.',
                    sender="vulner@rajatshenoi.pw"
                )
                mail.send(msg)
            except Exception as f:
                print("FAILED", f)
                app.logger.info(f"Failed to send email: {f}")
            raise e