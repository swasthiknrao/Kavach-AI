from PIL import Image, ImageDraw
import os

def create_shield_icon(size, output_path):
    # Create a new image with transparent background
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # Colors
    shield_color = '#4285f4'  # Google blue
    highlight_color = '#5c9bff'  # Lighter blue
    
    # Draw shield shape
    margin = size // 6
    shield_points = [
        (margin, margin),  # Top left
        (size - margin, margin),  # Top right
        (size - margin, size - margin * 2),  # Bottom right
        (size // 2, size - margin),  # Bottom point
        (margin, size - margin * 2),  # Bottom left
    ]
    draw.polygon(shield_points, fill=shield_color)
    
    # Draw K letter
    if size >= 32:  # Only draw K on larger icons
        letter_color = 'white'
        center_x = size // 2
        center_y = size // 2
        letter_size = size // 3
        
        # Draw K shape
        line_width = max(1, size // 16)
        # Vertical line
        draw.line([(center_x - letter_size//2, center_y - letter_size//2),
                  (center_x - letter_size//2, center_y + letter_size//2)],
                 fill=letter_color, width=line_width)
        # Diagonal lines
        draw.line([(center_x - letter_size//2, center_y),
                  (center_x + letter_size//2, center_y - letter_size//2)],
                 fill=letter_color, width=line_width)
        draw.line([(center_x - letter_size//2, center_y),
                  (center_x + letter_size//2, center_y + letter_size//2)],
                 fill=letter_color, width=line_width)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save the icon
    image.save(output_path, 'PNG')

def main():
    # Get the project root directory
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Create icons directory if it doesn't exist
    icons_dir = os.path.join(root_dir, 'icons')
    os.makedirs(icons_dir, exist_ok=True)
    
    # Generate icons in different sizes
    sizes = [16, 48, 128]
    for size in sizes:
        output_path = os.path.join(icons_dir, f'icon{size}.png')
        create_shield_icon(size, output_path)
        print(f'Created icon: {output_path}')

if __name__ == '__main__':
    main() 