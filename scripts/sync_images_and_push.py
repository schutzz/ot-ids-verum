import os
import shutil
import glob

repo_dir = r"C:\Users\user\.gemini\antigravity-ide\scratch\github_repo\ot-security-lab"
src_images_dir = r"C:\Users\user\.gemini\antigravity-ide\scratch\blog_project\Book_Project\images"
dst_images_dir = os.path.join(repo_dir, "images")

os.makedirs(dst_images_dir, exist_ok=True)

# 1. 画像ファイルを images/ へすべてコピー
if os.path.exists(src_images_dir):
    for img in os.listdir(src_images_dir):
        src_file = os.path.join(src_images_dir, img)
        dst_file = os.path.join(dst_images_dir, img)
        if os.path.isfile(src_file):
            shutil.copy(src_file, dst_file)
            print(f"Copied image: {img}")

# 2. books/ 配下のMarkdown内の画像リンクパスを /images/ に調整
books_dir = os.path.join(repo_dir, "books", "ot_ics_facility_security")
for md_path in glob.glob(os.path.join(books_dir, "*.md")):
    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = content.replace("../images/", "/images/")
    if new_content != content:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"Updated image paths in: {os.path.basename(md_path)}")

print("Zenn images sync script completed.")
