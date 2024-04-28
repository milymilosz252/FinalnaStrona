from PIL import Image
import os
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def compress_images(folder):
    file_paths = [os.path.join(folder, filename) for filename in os.listdir(folder)]
    with zipfile.ZipFile(f'{folder}.zip', 'w') as zip_file:
        for file_path in file_paths:
            zip_file.write(file_path, os.path.basename(file_path))

def convert_to_webp(input_path, output_path, quality=24):
    try:
        im = Image.open(input_path)
        im.save(output_path, quality=quality, lossless=False)
        return True
    except Exception as e:
        print(f"Conversion failed for {input_path}: {str(e)}")
        return False