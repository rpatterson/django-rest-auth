from rest_framework import serializers
from rest_framework import fields

from django_otp import forms

from .. import serializers as auth_serializers


class FormSerializer(serializers.Serializer):
    """
    Map a Django form onto a rest_framework serializer.
    """

    form_class = None
    form_kwargs = dict(user=lambda kwargs: kwargs['context']['request'].user)
    field_kwargs = dict(_choices='choices', strip='trim_whitespace')
    field_kwargs_excluded = {
        'widget', 'creation_counter', 'label_suffix', 'disabled', 'localize',
        'show_hidden_initial'}

    def __init__(self, instance=None, data=serializers.empty, **kwargs):
        """
        Translate the Django form fields to DRF serializer fields.
        """
        super(FormSerializer, self).__init__(
            instance=instance, data=data, **kwargs)

        self.form = self.form_class(data=data, **{
            key: value(kwargs)
            for key, value in self.form_kwargs.iteritems()})
        for name, field in self.form.fields.iteritems():
            field_class = getattr(fields, field.__class__.__name__)
            self.fields[name] = field_class(**{
                self.field_kwargs.get(key, key): value
                for key, value in vars(field).iteritems()
                if key not in self.field_kwargs_excluded})

    def is_valid(self, raise_exception=False):
        """
        Delegate to the Django form.
        """
        if not hasattr(self, '_validated_data'):
            self.form.is_valid()
            self._validated_data = self.form.cleaned_data
            self._errors = self.form.errors

        if self._errors and raise_exception:
            raise fields.ValidationError(self.errors)

        return not bool(self._errors)


class OTPTokenSerializer(FormSerializer):
    """
    Delegate to django_otp.forms:OTPTokenForm.
    """

    form_class = forms.OTPTokenForm


class NonEmptyLoginSerializer(auth_serializers.LoginSerializer):
    """
    Don't allow empty login credentials.
    """

    def validate_empty_values(self, data):
        """
        Don't allow empty login credentials.
        """
        try:
            return super(
                NonEmptyLoginSerializer, self).validate_empty_values(data)
        except fields.SkipField:  # pragma: no cover
            # TODO can't reproduce this in the APITestClient
            self.fail('required')
