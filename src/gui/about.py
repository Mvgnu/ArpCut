from PyQt5.QtWidgets import QMainWindow, QLabel, QVBoxLayout, QWidget, QHBoxLayout
from PyQt5.QtGui import QPixmap, QFont, QCursor
from PyQt5.QtCore import Qt

from ui.ui_about import Ui_MainWindow
from tools.qtools import clickable
from tools.utils import goto
from assets import twitter_icon, linkedin_icon, github_icon, reddit_icon, app_icon

class About(QMainWindow, Ui_MainWindow):
    # User's social links - EDIT THESE
    USER_DISCORD = 'YOUR_DISCORD_INVITE_OR_USERNAME'  # e.g., 'discord.gg/xxxx' or 'mvgnus'
    USER_TWITTER = 'YOUR_TWITTER_HANDLE'  # e.g., 'mvgnus_'
    USER_GITHUB = 'Mvgnu'  # GitHub username
    
    def __init__(self, elmocut, icon):
        super().__init__()
        self.elmocut = elmocut

        # Setup UI
        self.icon = icon
        self.setWindowIcon(icon)
        self.setupUi(self)
        
        # Increase window size to fit new content
        self.setMinimumSize(400, 500)
        self.setMaximumSize(400, 550)
        self.resize(400, 500)

        # App icon clicks to user's GitHub
        clickable(self.lblAppIcon).connect(self.user_github)
        self.setImage(self.lblAppIcon, app_icon)

        # Set app info
        self.lblAppName.setText(f'ArpCut v{self.elmocut.version}')
        self.lblMyName.setText('Mvgnus')
        self.lblMyName.setStyleSheet('font-weight: bold;')
        
        # Replace nickname label with "My Socials" section
        self.lblNickName.setText('— My Socials —')
        self.lblNickName.setStyleSheet('color: #3498db; font-weight: bold; margin-top: 10px;')
        
        # Repurpose existing social labels for user socials
        # Twitter -> X (Twitter)
        self.lblTwitter.setText('𝕏 Twitter')
        self.lblTwitter.setStyleSheet('color: white; font-size: 12px;')
        clickable(self.lblTwitter).connect(self.user_twitter)
        
        # LinkedIn -> Discord  
        self.lblLinkedIn.setText('💬 Discord')
        self.lblLinkedIn.setStyleSheet('color: #7289da; font-size: 12px;')
        clickable(self.lblLinkedIn).connect(self.user_discord)
        
        # GitHub -> User's GitHub
        self.lblGitHub.setText('🐙 GitHub')
        self.lblGitHub.setStyleSheet('color: #6cc644; font-size: 12px;')
        clickable(self.lblGitHub).connect(self.user_github)
        
        # Reddit -> Original elmoCut credits
        self.lblReddit.setText('📦 elmoCut')
        self.lblReddit.setStyleSheet('color: #ff4500; font-size: 12px;')
        self.lblReddit.setToolTip('View original elmoCut project')
        clickable(self.lblReddit).connect(self.original_project)
        
        # Add credits label at bottom
        self.add_credits_section()
    
    def add_credits_section(self):
        """Add original elmoCut credits at the bottom."""
        credits = QLabel(self.centralwidget)
        credits.setText('Based on elmoCut by Khaled El-Morshedy (elmoiv)')
        credits.setAlignment(Qt.AlignCenter)
        credits.setStyleSheet('color: gray; font-size: 10px; margin-top: 15px;')
        credits.setCursor(QCursor(Qt.PointingHandCursor))
        clickable(credits).connect(self.original_project)
        self.gridLayout.addWidget(credits, 5, 0, 1, 4)
    
    def showEvent(self, event):
        self.setStyleSheet(self.elmocut.styleSheet())
        event.accept()
    
    def setImage(self, label, icon_data):
        pix = QPixmap()
        pix.loadFromData(icon_data)
        label.setPixmap(pix)

    # User's social links
    def user_twitter(self):
        if self.USER_TWITTER and self.USER_TWITTER != 'YOUR_TWITTER_HANDLE':
            goto(f'https://twitter.com/{self.USER_TWITTER}')
    
    def user_discord(self):
        if self.USER_DISCORD and self.USER_DISCORD != 'YOUR_DISCORD_INVITE_OR_USERNAME':
            # Could be discord.gg link or just show username
            if 'discord.gg' in self.USER_DISCORD or 'discord.com' in self.USER_DISCORD:
                goto(self.USER_DISCORD)
            else:
                goto(f'https://discord.com/users/{self.USER_DISCORD}')
    
    def user_github(self):
        goto(f'https://github.com/{self.USER_GITHUB}')
    
    # Original project link
    def original_project(self):
        goto('https://github.com/elmoiv/elmocut')
