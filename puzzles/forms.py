import re
import unicodedata

from django import forms
from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.utils.translation import gettext as _

from puzzles.models import (
    Team,
    TeamMember,
    Survey,
    Hint,
)


def looks_spammy(s):
    # do not allow names that are only space or control characters
    if all(unicodedata.category(c).startswith(('Z', 'C')) for c in s): return True
    return re.search('https?://', s, re.IGNORECASE) is not None

class RegisterForm(forms.Form):
    team_id = forms.CharField(
        label=_('团队用户名'),
        max_length=100,
        help_text=(
            _('这是你的队伍在登录时使用的账户名。'
            '尽量设置得短些，且不含特殊字符。')
        ),
    )
    team_name = forms.CharField(
        label=_('团队显示名'),
        max_length=200,
        help_text=(
            _('这是你的队伍在记分板上显示的名字。')
        ),
    )
    password = forms.CharField(
        label=_('团队密码'),
        widget=forms.PasswordInput,
        help_text=_('要告诉别的队伍成员哦！'),
    )
    password2 = forms.CharField(
        label=_('重新输入密码'),
        widget=forms.PasswordInput,
    )

    def clean(self):
        cleaned_data = super(RegisterForm, self).clean()
        team_id = cleaned_data.get('team_id')
        password = cleaned_data.get('password')
        password2 = cleaned_data.get('password2')
        team_name = cleaned_data.get('team_name')

        if not team_name or looks_spammy(team_name):
            raise forms.ValidationError(
                _('此显示名不被允许。')
            )

        if password != password2:
            raise forms.ValidationError(
                _('密码前后不符。')
            )

        if User.objects.filter(username=team_id).exists():
            raise forms.ValidationError(
                _('此用户名已被其他队伍使用。')
            )

        if Team.objects.filter(team_name=team_name).exists():
            raise forms.ValidationError(
                _('此显示名已被其他队伍使用。')
            )

        return cleaned_data


def validate_team_member_email_unique(email):
    if TeamMember.objects.filter(email=email).exists():
        raise forms.ValidationError(
            _('此邮箱地址已被注册于另一个队伍。')
        )

class TeamMemberForm(forms.Form):
    name = forms.CharField(label=_('名字（必填）'), max_length=200)
    email = forms.EmailField(
        label=_('电子邮箱（选填）'),
        max_length=200,
        required=False,
        validators=[validate_email, validate_team_member_email_unique],
    )


def validate_team_emails(formset):
    emails = []
    for form in formset.forms:
        name = form.cleaned_data.get('name')
        if not name:
            raise forms.ValidationError(_('所有队伍成员都必须有名字。'))
        if looks_spammy(name):
            raise forms.ValidationError(_('此名字不被允许。'))
        email = form.cleaned_data.get('email')
        if email:
            emails.append(email)
    if not emails:
        raise forms.ValidationError(_('你需要至少一个电子邮箱地址。'))
    if len(emails) != len(set(emails)):
        raise forms.ValidationError(_('队伍成员间的电子邮箱地址不能重复。'))
    return emails

class TeamMemberFormset(forms.BaseFormSet):
    def clean(self):
        if any(self.errors):
            return
        validate_team_emails(self)

class TeamMemberModelFormset(forms.models.BaseModelFormSet):
    def clean(self):
        if any(self.errors):
            return
        emails = validate_team_emails(self)
        if (
            TeamMember.objects
            .exclude(team=self.data['team'])
            .filter(email__in=emails)
            .exists()
        ):
            raise forms.ValidationError(
                _('此邮箱地址已被注册于另一个队伍。')
            )


class SubmitAnswerForm(forms.Form):
    answer = forms.CharField(
        label=_('输入你的猜测：'),
        max_length=500,
        widget=forms.TextInput(attrs={'autofocus': True}),
    )


class RequestHintForm(forms.Form):
    hint_question = forms.CharField(
        label=(
            _('Describe everything you’ve tried on this puzzle. We will '
            'provide a hint to help you move forward. The more detail you '
            'provide, the less likely it is that we’ll tell you '
            'something you already know.')
        ),
        widget=forms.Textarea,
    )

    def __init__(self, team, *args, **kwargs):
        super(RequestHintForm, self).__init__(*args, **kwargs)
        notif_choices = [('all', _('Everyone')), ('none', _('No one'))]
        notif_choices.extend(team.get_emails(with_names=True))
        self.fields['notify_emails'] = forms.ChoiceField(
            label=_('When the hint is answered, send an email to:'),
            choices=notif_choices
        )


class HintStatusWidget(forms.Select):
    def get_context(self, name, value, attrs):
        self.choices = []
        for (option, desc) in Hint.STATUSES:
            if option == Hint.NO_RESPONSE:
                if value != Hint.NO_RESPONSE: continue
            elif option == Hint.ANSWERED:
                if value == Hint.OBSOLETE: continue
                if self.is_followup:
                    desc += _(' (as followup)')
            elif option == Hint.REFUNDED:
                if value == Hint.OBSOLETE: continue
                if self.is_followup:
                    desc += _(' (thread closed)')
            elif option == Hint.OBSOLETE:
                if value != Hint.OBSOLETE: continue
            self.choices.append((option, desc))
        if value == Hint.NO_RESPONSE:
            value = Hint.ANSWERED
            attrs['style'] = 'background-color: #ff3'
        return super(HintStatusWidget, self).get_context(name, value, attrs)

class AnswerHintForm(forms.ModelForm):
    class Meta:
        model = Hint
        fields = ('response', 'status')
        widgets = {'status': HintStatusWidget}


class SurveyForm(forms.ModelForm):
    class Meta:
        model = Survey
        exclude = ('team', 'puzzle', 'submitted_datetime')


# This form is a customization of forms.PasswordResetForm
class PasswordResetForm(forms.Form):
    team_id = forms.CharField(label=_('团队用户名'), max_length=100)

    def clean(self):
        cleaned_data = super(PasswordResetForm, self).clean()
        team_id = cleaned_data.get('team_id')
        team = Team.objects.filter(user__username=team_id).first()
        if team is None:
            raise forms.ValidationError(_('此用户名不存在。'))
        cleaned_data['team'] = team
        return cleaned_data
