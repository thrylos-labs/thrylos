# Contribution Guidelines

## Coding Standards

Our project follows industry-standard coding practices and principles to ensure readability, maintainability, and efficient collaboration. Here are the key standards you should follow:

- **Code Formatting**: Adhere to the Go [Effective Go](https://golang.org/doc/effective_go) guidelines for formatting and structuring your code. Use `gofmt` to automatically format your code before committing.
- **Naming Conventions**: Use clear, descriptive names for variables, functions, and methods. Follow Go's convention of using MixedCaps or mixedCaps rather than underscores to separate words.
- **Error Handling**: Always check for errors where they can occur, and handle them gracefully. Avoid ignoring errors unless explicitly intended.
- **Comments and Documentation**: Write comments and documentation for your code where necessary. Use Go's godoc conventions to document packages, functions, structs, and methods.
- **Tests**: Write unit tests for your functions and methods wherever possible. Aim for a high coverage and use table-driven tests where appropriate.

## Make sure we are

- **Optimising the blockchain**
- **Reducing unnecessary steps where possible**
- **Avoiding complicated implimentations**
- **Understanding the why each decision**


## Commit Message Conventions

Clear and consistent commit messages are vital for understanding the history of the project and the purpose of changes. Follow these guidelines for your commit messages:

- **Short Summary**: Start with a concise summary of the change in the first line, limited to 50 characters. Use imperative mood, as if completing the sentence "If applied, this commit will..."
- **Detailed Explanation**: Follow the summary with a blank line and then a more detailed explanation if needed, wrapped at 72 characters. Explain the context and reasoning behind the change, not just what has changed.
- **Issue References**: If your commit addresses a specific issue or task, include a reference to it at the end of the commit message. For example, "Fixes #123" or "Closes #456".
- **Atomic Commits**: Make small, atomic commits that encapsulate a single logical change. This practice makes it easier to review changes and roll back if necessary.

### Example Commit Message

\```plaintext
Improve error handling in transaction processing

- Refactor the transaction validation logic to separate method
- Add detailed error messages for each validation step
- Ensure all errors are logged with context for easier debugging

Fixes #789
\```

## Pull Requests

When submitting a pull request, ensure your code adheres to the project's coding standards and that all tests pass. Provide a clear description of the problem and solution, including any relevant issue numbers.

- **Description**: Include a concise description of the changes in your pull request. Mention how it addresses the issue or improves the project.
- **Testing**: Describe how the changes have been tested or provide instructions for reviewers to test the changes.
- **Screenshots**: If your changes include UI updates, include screenshots in your pull request description.

By following these guidelines, you contribute to a more efficient, understandable, and collaborative development process.
