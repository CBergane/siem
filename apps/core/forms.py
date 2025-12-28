from django import forms

INPUT_CLS = (
    "w-full px-4 py-2 bg-slate-900/60 border border-slate-700 rounded-lg "
    "text-slate-100 placeholder-slate-500 "
    "focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 "
    "transition"
)

TEXTAREA_CLS = (
    "w-full px-4 py-3 rounded-lg border transition resize-none "
    "bg-white text-slate-900 placeholder-slate-400 border-slate-300 "
    "focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 "
    "dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400 dark:border-slate-600"
)

class JoinRequestForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={
            "class": INPUT_CLS,
            "placeholder": "name@company.com",
            "autocomplete": "email",
        }),
    )
    full_name = forms.CharField(
        label="Full name",
        required=False,
        max_length=120,
        widget=forms.TextInput(attrs={
            "class": INPUT_CLS,
            "placeholder": "Your name",
            "autocomplete": "name",
        }),
    )
    company = forms.CharField(
        label="Company",
        required=False,
        max_length=120,
        widget=forms.TextInput(attrs={
            "class": INPUT_CLS,
            "placeholder": "Company / Organization",
            "autocomplete": "organization",
        }),
    )
    message = forms.CharField(
        label="Message (optional)",
        required=False,
        widget=forms.Textarea(attrs={
            "class": TEXTAREA_CLS,
            "placeholder": "Short context (e.g., what you need access to)",
            "rows": 5,
        }),
    )
