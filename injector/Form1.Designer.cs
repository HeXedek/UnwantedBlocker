namespace WinFormsApp13
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            button1 = new Button();
            Inject = new Label();
            button2 = new Button();
            label1 = new Label();
            SuspendLayout();
            // 
            // button1
            // 
            button1.Enabled = false;
            button1.Location = new Point(101, 36);
            button1.Name = "button1";
            button1.Size = new Size(320, 29);
            button1.TabIndex = 0;
            button1.Text = "Inject dll and start dll controller";
            button1.UseVisualStyleBackColor = true;
            button1.Click += button1_Click;
            // 
            // Inject
            // 
            Inject.AutoSize = true;
            Inject.ForeColor = Color.White;
            Inject.Location = new Point(191, 202);
            Inject.Name = "Inject";
            Inject.Size = new Size(212, 20);
            Inject.TabIndex = 2;
            Inject.Text = "made with no love by hexxadd";
            // 
            // button2
            // 
            button2.Location = new Point(269, 87);
            button2.Name = "button2";
            button2.Size = new Size(94, 29);
            button2.TabIndex = 3;
            button2.Text = "extarct files";
            button2.UseVisualStyleBackColor = true;
            button2.Click += button2_Click;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.ForeColor = Color.White;
            label1.Location = new Point(248, 119);
            label1.Name = "label1";
            label1.Size = new Size(134, 20);
            label1.TabIndex = 4;
            label1.Text = "click ts first or rape";
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(8F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = Color.FromArgb(15, 15, 15);
            ClientSize = new Size(599, 231);
            Controls.Add(label1);
            Controls.Add(button2);
            Controls.Add(Inject);
            Controls.Add(button1);
            MaximumSize = new Size(617, 278);
            MinimumSize = new Size(617, 278);
            Name = "Form1";
            Text = "george floyd antinigga";
            FormClosing += Form1_FormClosing;
            Load += Form1_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Button button1;
        private Label Inject;
        private Button button2;
        private Label label1;
    }
}
