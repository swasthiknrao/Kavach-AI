from flask import Blueprint, jsonify, request
from models.ai_modules.threat_intelligence import ThreatIntelligence
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
threat_intelligence_bp = Blueprint('threat_intelligence', __name__)
threat_intelligence = ThreatIntelligence()

@threat_intelligence_bp.route('/process', methods=['POST'])
async def process_threat_data():
    """Process threat data from multiple sources"""
    try:
        data = request.get_json()
        sources = data.get('sources', [])
        
        if not sources:
            return jsonify({
                'error': 'No threat sources provided'
            }), 400
            
        report = await threat_intelligence.process_threat_data(sources)
        
        if report:
            return jsonify({
                'status': 'success',
                'report': report
            })
        else:
            return jsonify({
                'error': 'Failed to process threat data'
            }), 500
            
    except Exception as e:
        logger.error(f"Error in process_threat_data: {e}")
        return jsonify({
            'error': str(e)
        }), 500

@threat_intelligence_bp.route('/emerging-threats', methods=['GET'])
def get_emerging_threats():
    """Get list of emerging threats"""
    try:
        threats = threat_intelligence.get_emerging_threats()
        return jsonify({
            'status': 'success',
            'threats': threats
        })
    except Exception as e:
        logger.error(f"Error in get_emerging_threats: {e}")
        return jsonify({
            'error': str(e)
        }), 500

@threat_intelligence_bp.route('/trends', methods=['GET'])
def get_trends():
    """Get threat trends analysis"""
    try:
        trends = threat_intelligence.analyze_trends()
        return jsonify({
            'status': 'success',
            'trends': trends
        })
    except Exception as e:
        logger.error(f"Error in get_trends: {e}")
        return jsonify({
            'error': str(e)
        }), 500

@threat_intelligence_bp.route('/recommendations', methods=['GET'])
def get_recommendations():
    """Get security recommendations"""
    try:
        patterns = {
            'temporal': threat_intelligence.analyze_temporal_patterns([]),
            'indicator': threat_intelligence.analyze_indicator_patterns([]),
            'emerging': threat_intelligence.detect_emerging_threats([])
        }
        
        recommendations = threat_intelligence.generate_recommendations(patterns)
        return jsonify({
            'status': 'success',
            'recommendations': recommendations
        })
    except Exception as e:
        logger.error(f"Error in get_recommendations: {e}")
        return jsonify({
            'error': str(e)
        }), 500

@threat_intelligence_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """Get threat statistics"""
    try:
        stats = {
            'new_threats_24h': threat_intelligence.count_new_threats(),
            'high_confidence_threats': threat_intelligence.count_high_confidence_threats(),
            'total_threats': len(threat_intelligence.threat_database),
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
    except Exception as e:
        logger.error(f"Error in get_statistics: {e}")
        return jsonify({
            'error': str(e)
        }), 500

@threat_intelligence_bp.route('/indicators', methods=['GET'])
def get_indicators():
    """Get threat indicators analysis"""
    try:
        # Get all indicators from the threat database
        all_indicators = [
            indicator
            for threat in threat_intelligence.threat_database.values()
            for indicator in threat['indicators']
        ]
        
        analysis = {
            'common': threat_intelligence.find_common_indicators(all_indicators),
            'correlations': threat_intelligence.calculate_indicator_correlations(all_indicators),
            'emerging': threat_intelligence.detect_emerging_indicators(all_indicators)
        }
        
        return jsonify({
            'status': 'success',
            'analysis': analysis
        })
    except Exception as e:
        logger.error(f"Error in get_indicators: {e}")
        return jsonify({
            'error': str(e)
        }), 500 