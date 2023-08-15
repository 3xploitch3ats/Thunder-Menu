# Charger les assemblies System.Windows.Forms et System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Définir le script en tant que chaîne
$script = @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
using System.IO.Compression;
using System.IO;

public class BinarySquarePatternGenerator
{
    public static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        Form form = new Form();
        form.Text = "Générateur de Motif de Carrés";
        form.Width = 800; // Ajuster la largeur de la fenêtre
        form.Height = 600; // Ajuster la hauteur de la fenêtre
        form.StartPosition = FormStartPosition.CenterScreen;

        TextBox textBox = new TextBox();
        textBox.Multiline = true;
        textBox.ScrollBars = ScrollBars.Vertical;
        textBox.Width = form.Width - 40;
        textBox.Height = form.Height - 300;
        textBox.Location = new Point(20, 20);
        form.Controls.Add(textBox);

        PictureBox pictureBox = new PictureBox();
        pictureBox.Location = new Point(20, textBox.Bottom + 10);
        pictureBox.Width = form.Width - 40;
        pictureBox.Height = form.Height - textBox.Height - 100;
        form.Controls.Add(pictureBox);

        Button loadButton = new Button();
        loadButton.Text = "Charger un fichier ZIP";
        loadButton.Location = new Point(20, pictureBox.Bottom + 10);
        form.Controls.Add(loadButton);

        Button generateButton = new Button();
        generateButton.Text = "Générer";
        generateButton.Location = new Point(loadButton.Right + 10, pictureBox.Bottom + 10);
        generateButton.Enabled = false;
        form.Controls.Add(generateButton);

        Button saveButton = new Button();
        saveButton.Text = "Enregistrer";
        saveButton.Location = new Point(generateButton.Right + 10, pictureBox.Bottom + 10);
        saveButton.Enabled = false;
        form.Controls.Add(saveButton);

        loadButton.Click += (sender, e) =>
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Fichiers ZIP|*.zip";
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string zipPath = openFileDialog.FileName;
                byte[] binaryData = File.ReadAllBytes(zipPath);
                string hexText = BitConverter.ToString(binaryData).Replace("-", "");
                string binaryText = "";
                foreach (char c in hexText)
                {
                    binaryText += Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0');
                }
                textBox.Text = binaryText;
                generateButton.Enabled = true;
            }
        };

        generateButton.Click += (sender, e) =>
        {
            string binaryText = textBox.Text;
            int imageSize = (int)Math.Ceiling(Math.Sqrt(binaryText.Length));

            Bitmap bitmap = new Bitmap(imageSize, imageSize);
            for (int i = 0; i < binaryText.Length; i++)
            {
                int x = i % imageSize;
                int y = i / imageSize;
                Color color = (binaryText[i] == '1') ? Color.Black : Color.White;
                bitmap.SetPixel(x, y, color);
            }

            pictureBox.Image = bitmap;
            saveButton.Enabled = true;
        };

        saveButton.Click += (sender, e) =>
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Images BMP|*.bmp";
            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                pictureBox.Image.Save(saveFileDialog.FileName, ImageFormat.Bmp);
                MessageBox.Show("Motif de carrés généré et enregistré sous " + saveFileDialog.FileName);
            }
        };

        form.Controls.Add(loadButton);
        form.Controls.Add(generateButton);
        form.Controls.Add(saveButton);

        Application.Run(form);
    }
}
"@

# Exécuter le script
Add-Type -TypeDefinition $script -ReferencedAssemblies System.Drawing, System.Windows.Forms

# Appeler la méthode Main pour exécuter le formulaire
[BinarySquarePatternGenerator]::Main()
