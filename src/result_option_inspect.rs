pub trait ResultInspector<T, E> {
    fn inspect(self, inspector_function: impl FnOnce(&T)) -> Self;
    fn inspect_err(self, inspector_function: impl FnOnce(&E)) -> Self;
}

impl<T, E> ResultInspector<T, E> for Result<T, E> {
    fn inspect(self, inspector_function: impl FnOnce(&T)) -> Self {
        match &self {
            Ok(value) => inspector_function(value),
            Err(_) => (),
        }
        self
    }

    fn inspect_err(self, inspector_function: impl FnOnce(&E)) -> Self {
        match &self {
            Ok(_) => (),
            Err(e) => inspector_function(e),
        }
        self
    }
}

impl<T, E> ResultInspector<T, E> for &Result<T, E> {
    fn inspect(self, inspector_function: impl FnOnce(&T)) -> Self {
        match &self {
            Ok(value) => inspector_function(value),
            Err(_) => (),
        }
        self
    }

    fn inspect_err(self, inspector_function: impl FnOnce(&E)) -> Self {
        match &self {
            Ok(_) => (),
            Err(e) => inspector_function(e),
        }
        self
    }
}

pub trait OptionInspector<T> {
    fn inspect(self, inspector_function: impl FnOnce(&T)) -> Self;
    fn inspect_none(self, inspector_function: impl FnOnce()) -> Self;
}

impl<T> OptionInspector<T> for Option<T> {
    fn inspect(self, inspector_function: impl FnOnce(&T)) -> Self {
        match &self {
            Some(value) => inspector_function(value),
            None => (),
        }
        self
    }

    fn inspect_none(self, inspector_function: impl FnOnce()) -> Self {
        match &self {
            Some(_) => (),
            None => inspector_function(),
        }
        self
    }
}

impl<T> OptionInspector<T> for &Option<T> {
    fn inspect(self, inspector_function: impl FnOnce(&T)) -> Self {
        match &self {
            Some(value) => inspector_function(value),
            None => (),
        }
        self
    }

    fn inspect_none(self, inspector_function: impl FnOnce()) -> Self {
        match &self {
            Some(_) => (),
            None => inspector_function(),
        }
        self
    }
}
