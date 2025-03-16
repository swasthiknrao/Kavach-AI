import React, { useState, useEffect } from 'react';
import {
    Box,
    Card,
    CardContent,
    Typography,
    Grid,
    CircularProgress,
    Alert,
    List,
    ListItem,
    ListItemText,
    Chip,
    Divider
} from '@mui/material';
import {
    Timeline,
    TimelineItem,
    TimelineSeparator,
    TimelineConnector,
    TimelineContent,
    TimelineDot
} from '@mui/lab';
import {
    Warning as WarningIcon,
    Security as SecurityIcon,
    Trending as TrendingIcon,
    Analytics as AnalyticsIcon
} from '@mui/icons-material';

interface Threat {
    id: string;
    type: string;
    confidence: number;
    indicators: string[];
    first_seen: string;
}

interface Recommendation {
    priority: string;
    type: string;
    action: string;
}

interface Statistics {
    new_threats_24h: number;
    high_confidence_threats: number;
    total_threats: number;
    last_updated: string;
}

interface TrendData {
    counts: Record<string, number>;
    trend: number;
}

interface Trends {
    daily: TrendData;
    weekly: TrendData;
    monthly: TrendData;
}

const ThreatIntelligence: React.FC = () => {
    const [emergingThreats, setEmergingThreats] = useState<Threat[]>([]);
    const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
    const [statistics, setStatistics] = useState<Statistics | null>(null);
    const [trends, setTrends] = useState<Trends | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                setLoading(true);
                setError(null);

                // Fetch emerging threats
                const threatsResponse = await fetch('/api/threat-intelligence/emerging-threats');
                const threatsData = await threatsResponse.json();
                if (threatsData.status === 'success') {
                    setEmergingThreats(threatsData.threats);
                }

                // Fetch recommendations
                const recommendationsResponse = await fetch('/api/threat-intelligence/recommendations');
                const recommendationsData = await recommendationsResponse.json();
                if (recommendationsData.status === 'success') {
                    setRecommendations(recommendationsData.recommendations);
                }

                // Fetch statistics
                const statisticsResponse = await fetch('/api/threat-intelligence/statistics');
                const statisticsData = await statisticsResponse.json();
                if (statisticsData.status === 'success') {
                    setStatistics(statisticsData.statistics);
                }

                // Fetch trends
                const trendsResponse = await fetch('/api/threat-intelligence/trends');
                const trendsData = await trendsResponse.json();
                if (trendsData.status === 'success') {
                    setTrends(trendsData.trends);
                }

            } catch (err) {
                setError('Failed to fetch threat intelligence data');
                console.error('Error fetching threat data:', err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        // Refresh data every 5 minutes
        const interval = setInterval(fetchData, 5 * 60 * 1000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
                <CircularProgress />
            </Box>
        );
    }

    if (error) {
        return (
            <Box m={2}>
                <Alert severity="error">{error}</Alert>
            </Box>
        );
    }

    return (
        <Box p={3}>
            <Typography variant="h4" gutterBottom>
                Threat Intelligence Dashboard
            </Typography>

            {/* Statistics Cards */}
            <Grid container spacing={3} mb={3}>
                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Typography color="textSecondary" gutterBottom>
                                New Threats (24h)
                            </Typography>
                            <Typography variant="h4">
                                {statistics?.new_threats_24h || 0}
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Typography color="textSecondary" gutterBottom>
                                High Confidence Threats
                            </Typography>
                            <Typography variant="h4">
                                {statistics?.high_confidence_threats || 0}
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Typography color="textSecondary" gutterBottom>
                                Total Threats
                            </Typography>
                            <Typography variant="h4">
                                {statistics?.total_threats || 0}
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                    <Card>
                        <CardContent>
                            <Typography color="textSecondary" gutterBottom>
                                Last Updated
                            </Typography>
                            <Typography variant="body1">
                                {statistics?.last_updated
                                    ? new Date(statistics.last_updated).toLocaleString()
                                    : 'N/A'}
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>

            {/* Emerging Threats */}
            <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                    <Card>
                        <CardContent>
                            <Typography variant="h6" gutterBottom>
                                Emerging Threats
                            </Typography>
                            <List>
                                {emergingThreats.map((threat) => (
                                    <React.Fragment key={threat.id}>
                                        <ListItem>
                                            <ListItemText
                                                primary={
                                                    <Box display="flex" alignItems="center" gap={1}>
                                                        <Typography variant="subtitle1">
                                                            {threat.type}
                                                        </Typography>
                                                        <Chip
                                                            size="small"
                                                            label={`${(threat.confidence * 100).toFixed(0)}%`}
                                                            color={threat.confidence >= 0.8 ? 'error' : 'warning'}
                                                        />
                                                    </Box>
                                                }
                                                secondary={
                                                    <>
                                                        <Typography variant="body2" color="textSecondary">
                                                            First seen: {new Date(threat.first_seen).toLocaleString()}
                                                        </Typography>
                                                        <Box mt={1}>
                                                            {threat.indicators.map((indicator, index) => (
                                                                <Chip
                                                                    key={index}
                                                                    label={indicator}
                                                                    size="small"
                                                                    variant="outlined"
                                                                    style={{ margin: '0 4px 4px 0' }}
                                                                />
                                                            ))}
                                                        </Box>
                                                    </>
                                                }
                                            />
                                        </ListItem>
                                        <Divider />
                                    </React.Fragment>
                                ))}
                            </List>
                        </CardContent>
                    </Card>
                </Grid>

                {/* Recommendations */}
                <Grid item xs={12} md={6}>
                    <Card>
                        <CardContent>
                            <Typography variant="h6" gutterBottom>
                                Security Recommendations
                            </Typography>
                            <Timeline>
                                {recommendations.map((recommendation, index) => (
                                    <TimelineItem key={index}>
                                        <TimelineSeparator>
                                            <TimelineDot
                                                color={
                                                    recommendation.priority === 'high'
                                                        ? 'error'
                                                        : recommendation.priority === 'medium'
                                                        ? 'warning'
                                                        : 'info'
                                                }
                                            >
                                                {recommendation.type === 'monitoring' ? (
                                                    <AnalyticsIcon />
                                                ) : recommendation.type === 'protection' ? (
                                                    <SecurityIcon />
                                                ) : (
                                                    <WarningIcon />
                                                )}
                                            </TimelineDot>
                                            {index < recommendations.length - 1 && <TimelineConnector />}
                                        </TimelineSeparator>
                                        <TimelineContent>
                                            <Typography variant="subtitle2" color="textSecondary">
                                                {recommendation.type.toUpperCase()}
                                            </Typography>
                                            <Typography>{recommendation.action}</Typography>
                                        </TimelineContent>
                                    </TimelineItem>
                                ))}
                            </Timeline>
                        </CardContent>
                    </Card>
                </Grid>

                {/* Trends */}
                <Grid item xs={12}>
                    <Card>
                        <CardContent>
                            <Typography variant="h6" gutterBottom>
                                Threat Trends
                            </Typography>
                            <Grid container spacing={2}>
                                {trends && Object.entries(trends).map(([period, data]) => (
                                    <Grid item xs={12} md={4} key={period}>
                                        <Card variant="outlined">
                                            <CardContent>
                                                <Typography variant="subtitle1" gutterBottom>
                                                    {period.charAt(0).toUpperCase() + period.slice(1)} Trend
                                                </Typography>
                                                <Box display="flex" alignItems="center" gap={1}>
                                                    <TrendingIcon
                                                        color={data.trend > 0 ? 'error' : 'success'}
                                                    />
                                                    <Typography>
                                                        {data.trend > 0 ? 'Increasing' : 'Decreasing'}
                                                        {' '}
                                                        ({Math.abs(data.trend).toFixed(2)})
                                                    </Typography>
                                                </Box>
                                            </CardContent>
                                        </Card>
                                    </Grid>
                                ))}
                            </Grid>
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>
        </Box>
    );
};

export default ThreatIntelligence; 