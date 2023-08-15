# Charger les assemblies System.Windows.Forms et System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Définir le script en tant que chaîne
$script = @"
using System;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Windows.Forms;

public class BinarySquarePatternGenerator
{
    public static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        Form form = new Form();
        form.Text = "Générateur de Motif de Carrés";
        form.Width = 800;
        form.Height = 600;
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
        loadButton.Text = "Charger une image BMP";
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

        Bitmap loadedBitmap = null;

        loadButton.Click += (sender, e) =>
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Images BMP|*.bmp";
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string imagePath = openFileDialog.FileName;
                loadedBitmap = new Bitmap(imagePath);
                pictureBox.Image = loadedBitmap;
                generateButton.Enabled = true;
            }
        };

        generateButton.Click += (sender, e) =>
        {
            if (loadedBitmap == null)
            {
                MessageBox.Show("Veuillez charger une image d'abord.");
                return;
            }

            string binaryText = GenerateBinaryPattern(loadedBitmap);
            textBox.Text = binaryText;
            saveButton.Enabled = true;
        };

        saveButton.Click += (sender, e) =>
        {
            if (string.IsNullOrWhiteSpace(textBox.Text))
            {
                MessageBox.Show("Le contenu du TextBox est vide. Veuillez générer le motif d'abord.");
                return;
            }

            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Fichiers ZIP|*.zip";
            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                string binaryText = textBox.Text;
                byte[] binaryBytes = ConvertBinaryTextToBytes(binaryText);

                File.WriteAllBytes(saveFileDialog.FileName, binaryBytes);
                MessageBox.Show("Contenu enregistré dans " + saveFileDialog.FileName);
            }
        };

        form.Controls.Add(loadButton);
        form.Controls.Add(generateButton);
        form.Controls.Add(saveButton);

        Application.Run(form);
    }

    private static string GenerateBinaryPattern(Bitmap bitmap)
    {
        string binaryText = "";

        for (int y = 0; y < bitmap.Height; y++)
        {
            for (int x = 0; x < bitmap.Width; x++)
            {
                Color color = bitmap.GetPixel(x, y);
                int grayscale = (color.R + color.G + color.B) / 3;
                int threshold = 128;

                binaryText += (grayscale < threshold) ? "1" : "0";
            }
            binaryText += Environment.NewLine;
        }

        return binaryText;
    }

    private static byte[] ConvertBinaryTextToBytes(string binaryText)
    {
        binaryText = binaryText.Replace(Environment.NewLine, "");
        int numOfBytes = binaryText.Length / 8;
        byte[] bytes = new byte[numOfBytes];

        for (int i = 0; i < numOfBytes; i++)
        {
            string byteStr = binaryText.Substring(i * 8, 8);
            byte byteValue = Convert.ToByte(byteStr, 2);
            bytes[i] = byteValue;
        }

        return bytes;
    }
}
"@

# Exécuter le script
Add-Type -TypeDefinition $script -ReferencedAssemblies System.Drawing, System.Windows.Forms, System.IO.Compression

# Appeler la méthode Main pour exécuter le formulaire
[BinarySquarePatternGenerator]::Main()
