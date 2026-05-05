from django import forms


class ScanSubmissionForm(forms.Form):
    target_url = forms.URLField(
        label='Website URL',
        max_length=500,
        widget=forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://example.com'}),
    )
