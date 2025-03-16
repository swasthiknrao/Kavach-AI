class URLAnalyzer {
    constructor() {
        this.apiEndpoint = 'http://localhost:5000/api/analyze';
    }

    async analyzeURL(url) {
        try {
            const screenshot = await this.captureScreenshot();
            const behavior = await this.collectBehaviorData();

            const response = await fetch(this.apiEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    screenshot: screenshot,
                    behavior: behavior
                })
            });

            return await response.json();
        } catch (error) {
            console.error('Error analyzing URL:', error);
            return null;
        }
    }

    async captureScreenshot() {
        try {
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            const video = document.createElement('video');

            // Get the viewport dimensions
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;

            // Capture the current tab
            const stream = await navigator.mediaDevices.getDisplayMedia({
                preferCurrentTab: true
            });
            
            video.srcObject = stream;
            await video.play();

            // Draw video frame to canvas
            context.drawImage(video, 0, 0, canvas.width, canvas.height);
            
            // Stop all tracks
            stream.getTracks().forEach(track => track.stop());
            
            // Convert to base64
            return canvas.toDataURL('image/png').split(',')[1];
        } catch (error) {
            console.error('Screenshot error:', error);
            return '';
        }
    }

    async collectBehaviorData() {
        return {
            page_text: document.body.innerText,
            user_actions: [],
            metadata: {
                page_load_time: performance.now(),
                user_interactions: 0,
                form_fields: this.getFormFields()
            }
        };
    }

    getFormFields() {
        const forms = document.getElementsByTagName('form');
        const fields = [];
        for (let form of forms) {
            const inputs = form.getElementsByTagName('input');
            for (let input of inputs) {
                fields.push(input.name || input.id || input.type);
            }
        }
        return fields;
    }
}

window.URLAnalyzer = new URLAnalyzer(); 